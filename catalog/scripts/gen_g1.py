# -*- coding: utf-8 -*-
# Generates g1_standards.json (standardised / registered JWT claims)
import json, sys

IANA = "https://www.iana.org/assignments/jwt/jwt.xhtml"
def RFC(n): return f"https://www.rfc-editor.org/rfc/rfc{n}"
def DRAFT(d): return f"https://www.ietf.org/archive/id/{d}.txt"
CORE = "https://openid.net/specs/openid-connect-core-1_0.html"
FCL = "https://openid.net/specs/openid-connect-frontchannel-1_0.html"
BCL = "https://openid.net/specs/openid-connect-backchannel-1_0.html"
IDAS = "https://openid.net/specs/openid-ida-verified-claims-1_0-final.html"
IDAC = "https://openid.net/specs/openid-connect-4-ida-claims-1_0-final.html"
FED = "https://openid.net/specs/openid-federation-1_0.html"
SSF = "https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html"
CAEP = "https://openid.net/specs/openid-caep-1_0-final.html"
RISC = "https://openid.net/specs/openid-risc-1_0-final.html"
TXN = DRAFT("draft-ietf-oauth-transaction-tokens-11")
IDJAG = DRAFT("draft-ietf-oauth-identity-assertion-authz-grant-06")
CHAIN = DRAFT("draft-ietf-oauth-identity-chaining-17")
SDVC = DRAFT("draft-ietf-oauth-sd-jwt-vc-27")
TSL = DRAFT("draft-ietf-oauth-status-list-21")
STPL = DRAFT("draft-ietf-stir-certificates-ocsp-14")
ENTRA_AT = "https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference"
ENTRA_ID = "https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference"
ENTRA_OPT = "https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference"

K_RFC = "標準（IETF RFC）"
K_OIDF = "標準（OpenID Foundation 最終版）"
K_DRAFT = "草案（IETF・OIDF）"
K_OTHER = "IANA 登録（その他の標準化団体）"

SUPMAP = {"D": "既定", "C": "設定で追加", "N": "独自の名前で", "H": "フック・式で可",
          "X": "不可・未対応", "U": "不明"}
VENDORS = ["Entra", "Keycloak", "Auth0", "Okta", "Cognito"]

ROWS = []

def mult(vt):
    v = vt.lower()
    if "または array" in v or "or array" in v or "単一または配列" in v:
        return "単一または配列（揺れあり）"
    if v.startswith("array"):
        return "配列"
    return "単一"

def cmp_default(vt):
    v = vt.lower()
    if "stringoruri" in v:
        return "大小区別の完全一致"
    if v.startswith("number") or v.startswith("boolean") or v.startswith("object") or v.startswith("integer"):
        return "該当なし"
    return "不明"

def R(name, cat, purpose, kind, source, url, vt, token, notes, sup="UUUUU",
      verified=True, custom="標準", **kw):
    row = {
        "name": name, "category": cat, "purpose": purpose, "source_kind": kind,
        "source": source, "url": url, "value_type": vt, "token": token,
        "support": {v: SUPMAP[c] for v, c in zip(VENDORS, sup)},
        "is_custom": custom, "notes": notes, "verified": verified,
        "status": kw.get("status", "草案" if kind == K_DRAFT else "最終"),
        "change_controller": kw.get("cc", "IESG" if kind == K_RFC else ("OpenID Foundation" if kind == K_OIDF else "不明")),
        "writer": kw.get("writer", "発行者（権威ある情報源）"),
        "mutability": kw.get("mut", "不明"),
        "freshness": kw.get("fresh", "発行時点で固定（寿命内は古いまま）"),
        "authz_use": kw.get("authz", "不明"),
        "pii": kw.get("pii", "非該当"),
        "log_policy": kw.get("log", "記載なし"),
        "multiplicity": kw.get("multi", mult(vt)),
        "limit": kw.get("limit", "記載なし"),
        "comparison": kw.get("cmp", cmp_default(vt)),
        "uniqueness": kw.get("uniq", "該当なし"),
        "vocabulary": kw.get("vocab", "該当なし" if vt.startswith(("number", "boolean")) else "不明"),
        "synonym_group": kw.get("syn", "G-" + name.split(".")[0].replace("_", "-")),
        "checked_on": "2026-11-17",
    }
    ROWS.append(row)

VN = "ベンダー対応は research notes 02_idp-claims.md と Entra クレームリファレンス（" + ENTRA_AT + " ほか）で確認した範囲のみ記入、他は不明。"
NUM = "number (NumericDate)"

# =========================================================
# 1. RFC 7519 registered claims
# =========================================================
s7519 = "RFC 7519 §4.1."
R("iss", "発行者・宛先", "JWT を発行した主体（issuer）を示す。値の解釈はアプリ依存で、それ自体は署名鍵の正当性を保証しない。",
  K_RFC, s7519 + "1", RFC(7519), "string (StringOrURI)", "両方",
  "OPTIONAL（RFC 7519 では任意だがほぼ全プロファイルで必須化）。StringOrURI は変換・正規化なしで比較。Entra のマルチテナント（common/organizations）は issuer に {tenantid} テンプレートがあり tid で置換して比較。Cognito は ORIGINAL/UPDATED の 2 種の issuer 形式。" + VN,
  sup="DDDDD", authz="iss・aud などと組で可", uniq="全体で一意", vocab="URI", syn="G-issuer")
R("sub", "識別子", "JWT の主語（主体）を示す識別子。発行者の文脈内で一意（または全体で一意）であるべきで、発行者が違えば同じ値でも別主体。",
  K_RFC, s7519 + "2", RFC(7519), "string (StringOrURI)", "両方",
  "OPTIONAL。iss と組で解釈する。Entra の sub はアプリごとに異なる pairwise（共有キーは oid+tid）、Okta の AT の sub はログイン名（メール形式）で IDT の sub（00u...）と異なる、Cognito の sub は UUID として厳密検証しない、Auth0 は provider|id 形式でテナント内一意。" + VN,
  sup="DDDDD", authz="iss・aud などと組で可", pii="仮名の識別子", uniq="発行者内で一意", vocab="発行者ごと", syn="G-user-id")
R("aud", "発行者・宛先", "JWT の受け手（audience）を示す。受け手は自分が含まれない JWT を拒否しなければならない。",
  K_RFC, s7519 + "3", RFC(7519), "string (StringOrURI) または array of string", "両方",
  "OPTIONAL だが、受け手は自身を識別できない場合 reject（MUST）。単一文字列と配列の両形あり。Keycloak は既定で API を aud に含めない（Audience mapper / Audience Resolve が必要）、Auth0 は audience パラメータ省略で opaque AT、Cognito AT は既定で aud がなく client_id（resource パラメータ指定時のみ aud）。" + VN,
  sup="DCDDC", authz="iss・aud などと組で可", vocab="発行者ごと", syn="G-audience")
R("exp", "時刻・寿命", "これ以降は JWT を受理してはならない時刻（NumericDate）。失効（revocation）を意味するわけではない。",
  K_RFC, s7519 + "4", RFC(7519), NUM, "両方",
  "OPTIONAL。小さな clock skew の許容可（数分程度を推奨）。exp 前でもサインアウトや失効は検出できない（Cognito ドキュメントも明記）。SSF の SET では exp を使ってはならない。" + VN,
  sup="DDDDD", authz="補助のみ", fresh="該当なし", syn="G-exp")
R("nbf", "時刻・寿命", "この時刻より前は JWT を受理してはならないことを示す。",
  K_RFC, s7519 + "5", RFC(7519), NUM, "両方", "OPTIONAL。clock skew の許容可。Entra の ID/AT には nbf がある（Entra リファレンス）。" + VN,
  sup="DUUUU", authz="補助のみ", fresh="該当なし", syn="G-nbf")
R("iat", "時刻・寿命", "JWT が発行された時刻。トークンの年齢判定に使えるが、認証時刻（auth_time）とは別物。",
  K_RFC, s7519 + "6", RFC(7519), NUM, "両方",
  "OPTIONAL。Entra のリファレンスは iat を「認証が起きた時刻」と説明しており、OIDC の auth_time と混同しやすい点に注意。" + VN,
  sup="DDDDD", authz="補助のみ", fresh="該当なし", syn="G-iat")
R("jti", "トークン種別・メタ", "JWT の一意識別子。リプレイ防止に使える。値の衝突確率が無視できる形で割り当てる必要がある。",
  K_RFC, s7519 + "7", RFC(7519), "string", "両方",
  "OPTIONAL。大小区別。Entra は独自に uti（jti 相当）を使う。Auth0 は RFC 9068 プロファイルで jti。Cognito は失効有効化で jti / origin_jti が追加される。" + VN,
  sup="NUCUC", cmp="大小区別の完全一致", uniq="全体で一意", syn="G-jti")

# =========================================================
# 2. OpenID Connect Core 1.0 §2 (ID Token) + misc
# =========================================================
sc = "OpenID Connect Core 1.0 §2"
R("iss", "発行者・宛先", "ID トークンの発行者識別子（https スキームの URL、クエリ・フラグメントなし）。RP は Discovery の issuer と完全一致を確認する。",
  K_OIDF, sc, CORE, "string (URL)", "ID", "REQUIRED。大小区別の URL。" + VN, sup="DDDDD",
  authz="iss・aud などと組で可", cmp="大小区別の完全一致", uniq="全体で一意", vocab="URI", syn="G-issuer")
R("sub", "識別子", "発行者内でローカルに一意かつ再割り当てされないエンドユーザー識別子。iss と組でのみユーザーを特定できる。",
  K_OIDF, sc, CORE, "string (最大 255 ASCII 文字)", "ID",
  "REQUIRED。大小区別。§5.7 は iss+sub のみが安定した識別に使えると明記（email 等は不可）。public / pairwise の 2 方式（§8）。" + VN,
  sup="DDDDD", authz="iss・aud などと組で可", pii="仮名の識別子", mut="再割り当てなし", limit="255 ASCII 文字以内（MUST NOT exceed）",
  cmp="大小区別の完全一致", uniq="発行者内で一意", vocab="発行者ごと", syn="G-user-id")
R("aud", "発行者・宛先", "ID トークンの宛先（RP の client_id を含む）。ID トークンは API のアクセス許可には使わない。",
  K_OIDF, sc, CORE, "string または array of string", "ID",
  "REQUIRED。client_id を含まなければ拒否。他の audience を含む場合は信頼できるか確認。Okta はリソースサーバーは ID トークンで認可しないと明記。" + VN,
  sup="DDDDD", authz="iss・aud などと組で可", cmp="大小区別の完全一致", vocab="発行者ごと", syn="G-audience")
R("exp", "時刻・寿命", "ID トークンの有効期限。", K_OIDF, sc, CORE, NUM, "ID", "REQUIRED。" + VN, sup="DDDDD", fresh="該当なし", syn="G-exp")
R("iat", "時刻・寿命", "ID トークンの発行時刻。", K_OIDF, sc, CORE, NUM, "ID", "REQUIRED。" + VN, sup="DDDDD", fresh="該当なし", syn="G-iat")
R("auth_time", "認証の強さ・セッション", "エンドユーザーが認証した時刻。トークン発行時刻ではない。",
  K_OIDF, sc, CORE, NUM, "ID",
  "max_age 要求時または auth_time を Essential Claim として要求された場合は REQUIRED、それ以外は OPTIONAL。Entra では optional claim（ID トークン）、Okta・Cognito は既定で含む。" + VN,
  sup="CUUDD", authz="補助のみ", fresh="該当なし", syn="G-auth-time")
R("nonce", "監査・相関・イベント", "認証要求と ID トークンを結び付け、リプレイを防ぐ値。RP が要求に含めた値をそのまま返す。",
  K_OIDF, sc, CORE, "string", "ID",
  "認証要求に nonce があれば REQUIRED で同値。大小区別。IANA では RFC 9449（DPoP）も参照元として併記。" + VN,
  writer="呼び出し元・クライアントの申告", cmp="大小区別の完全一致", vocab="自由な文字列", syn="G-nonce")
R("acr", "認証の強さ・セッション", "認証が満たした Authentication Context Class Reference。値の意味は当事者間の合意による。",
  K_OIDF, sc, CORE, "string (StringOrURI)", "ID",
  "OPTIONAL。値 0 は ISO/IEC 29115 レベル1未満で金銭的価値のある資源に使ってはならない。RFC 9470（Step-up）は acr_values / max_age を要求パラメータとして使うが、それらはクレームではない。Entra の acr は v1.0 のみで 0/1（step-up は acrs）、Keycloak は既定 client scope acr の LoA mapper、Cognito は固定 4 レベル（段階展開中）。" + VN,
  sup="DDUDD", authz="補助のみ", vocab="発行者ごと", syn="G-acr")
R("amr", "認証の強さ・セッション", "認証に使われた方式の識別子の配列（例 pwd, mfa, otp）。認証の強さそのものの保証ではない。",
  K_OIDF, sc, CORE, "array of string", "ID",
  "OPTIONAL。値の語彙は RFC 8176 に登録（face, fpt, geo, hwk, iris, kba, mca, mfa, otp, pin, pwd, rba, retina, sc, sms, swk, tel, user, vbm, wia）。Entra は v1.0 basic claim／v2.0 では optional claim、Okta は IDT に既定、Cognito は固定レベル連動。" + VN,
  sup="CUUDD", authz="補助のみ", vocab="標準で列挙（RFC 8176 AMR Values レジストリ）", syn="G-amr")
R("azp", "クライアント・ワークロード", "ID トークンを発行された相手（authorized party = client_id）。aud が複数のときの判別に使う。",
  K_OIDF, sc, CORE, "string", "ID",
  "OPTIONAL。Entra は v2.0 AT で appid の代替として azp（GUID）を出す。Auth0 の既定 AT プロファイルにも azp。" + VN,
  sup="DUDUU", cmp="大小区別の完全一致", vocab="発行者ごと", syn="G-client-id")
R("at_hash", "開示・暗号・検証補助", "同時発行されたアクセストークンのハッシュ（左半分の base64url）。ID トークンと AT の結び付けを検証する。",
  K_OIDF, "OpenID Connect Core 1.0 §3.1.3.6 / §3.2.2.10", CORE, "string (base64url)", "ID",
  "IANA 参照は §2。Implicit/Hybrid で AT と同時発行時に必要。Entra は /authorize から AT と共に発行された場合のみ含む。" + VN,
  sup="DUUUU", writer="発行者が派生", fresh="該当なし", cmp="大小区別の完全一致", syn="G-token-hash")
R("c_hash", "開示・暗号・検証補助", "認可コードのハッシュ。Hybrid フローでコード差し替えを検出する。",
  K_OIDF, "OpenID Connect Core 1.0 §3.3.2.11", CORE, "string (base64url)", "ID", "Hybrid フローで code と ID トークンを同時返却する場合に使用。" + VN,
  writer="発行者が派生", fresh="該当なし", cmp="大小区別の完全一致", syn="G-token-hash")
R("sub_jwk", "鍵・送信者制約", "Self-Issued OP の ID トークン署名検証に使う公開鍵（JWK）。",
  K_OIDF, "OpenID Connect Core 1.0 §7.4", CORE, "object (JWK)", "ID",
  "Self-Issued OpenID Provider でのみ使用（通常の OP では使わない）。sub はこの鍵のサムプリントから派生。" + VN,
  writer="本人が編集できる", syn="G-key")
R("_claim_names", "開示・暗号・検証補助", "Aggregated / Distributed Claims で、クレーム名と取得元（_claim_sources のキー）を対応付ける。",
  K_OIDF, "OpenID Connect Core 1.0 §5.6.2", CORE, "object", "両方",
  "Entra は groups が JWT で 200 件（SAML 150）を超えると groups の代わりに _claim_names / _claim_sources を出す（返る URL は旧 Azure AD Graph なので Microsoft Graph を組み立てよ）。" + VN,
  sup="DUUUU", fresh="都度照会が必要", limit="Entra: groups 200 件超（JWT）で groups 欠落・本クレームに置換", syn="G-claim-sources")
R("_claim_sources", "開示・暗号・検証補助", "Aggregated（JWT を内包）/ Distributed（endpoint と access_token）クレームの取得元を示す。",
  K_OIDF, "OpenID Connect Core 1.0 §5.6.2", CORE, "object", "両方",
  "メンバー: JWT（Aggregated）、endpoint / access_token（Distributed）。Entra の groups overage で使用。" + VN,
  sup="DUUUU", fresh="都度照会が必要", syn="G-claim-sources")

# =========================================================
# 3. OIDC Core §5.1 standard claims
# =========================================================
s51 = "OpenID Connect Core 1.0 §5.1"
P_NOTE = "§5.7: iss+sub 以外のクレームはユーザー識別・一意性に使ってはならない（変更・再利用され得る）。"
def P(name, purpose, vt, notes, sup="UUUUU", pii="直接識別できる個人情報", **kw):
    kw.setdefault("writer", "本人が編集できる")
    kw.setdefault("mut", "改名・変更あり")
    kw.setdefault("authz", "不可（表示・監査用）")
    kw.setdefault("uniq", "なし")
    R(name, kw.pop("cat", "プロフィール・連絡先"), purpose, K_OIDF, s51, CORE, vt, "両方",
      notes + " " + P_NOTE + VN, sup=sup, pii=pii, **kw)

P("name", "表示用のフルネーム（敬称等を含み得る）。", "string", "profile スコープ。ロケール・言語タグ付き（name#ja-Kana-JP 等）可。Entra は mutable で表示専用と明記、profile スコープで取得。", sup="DUUUU", vocab="自由な文字列", syn="G-name")
P("given_name", "名（ファーストネーム）。", "string", "profile スコープ。複数の名はスペース区切り。Entra は optional claim。", sup="CUUUU", vocab="自由な文字列", syn="G-name")
P("family_name", "姓。", "string", "profile スコープ。Entra は optional claim。", sup="CUUUU", vocab="自由な文字列", syn="G-name")
P("middle_name", "ミドルネーム。", "string", "profile スコープ。使わない文化もある。", vocab="自由な文字列", syn="G-name")
P("nickname", "通称・愛称。given_name と同じとは限らない。", "string", "profile スコープ。", vocab="自由な文字列", syn="G-name")
P("preferred_username", "ユーザーが呼ばれたい短い名前。一意である保証はなく、認可やキーには使えない。",
  "string", "profile スコープ。§5.1 で RP は一意性を前提にしてはならないと明記。Entra は v2.0 で既定、mutable で認可に使うなと明記。", sup="DUUUU", vocab="自由な文字列", syn="G-username")
P("profile", "プロフィールページの URL。", "string (URL)", "profile スコープ。", vocab="URI", syn="G-profile-url")
P("picture", "プロフィール画像の URL（画像ファイルを指す）。", "string (URL)", "profile スコープ。", vocab="URI", syn="G-picture")
P("website", "Web ページ／ブログの URL。", "string (URL)", "profile スコープ。", vocab="URI", syn="G-website")
P("email", "ユーザーの希望するメールアドレス（RFC 5322 addr-spec）。一意である保証はない。",
  "string", "email スコープ。§5.1 で一意性を前提にしてはならないと明記。Entra は guest には既定、メンバーは optional claim。認可に使うなと明記。", sup="CUUUU", vocab="自由な文字列", syn="G-email")
P("email_verified", "email の値が検証済みかどうか。検証の方法や時期は発行者依存。", "boolean",
  "email スコープ。true は検証手段が取られたことのみを意味し、現在も所有していることまでは保証しない。", writer="発行者（権威ある情報源）", syn="G-email-verified")
P("gender", "性別（female / male、またはその他の値）。", "string", "profile スコープ。", pii="機微な個人情報", vocab="標準で列挙（female, male; 他の値も可）", syn="G-gender")
P("birthdate", "生年月日（ISO 8601 YYYY-MM-DD、年のみ YYYY、年非開示は 0000）。", "string (ISO 8601 date)", "profile スコープ。", vocab="自由な文字列", syn="G-birthdate")
P("zoneinfo", "タイムゾーン（tz database 名。例 Europe/Paris）。", "string", "profile スコープ。", pii="非該当", vocab="標準で列挙（IANA tz database）", syn="G-zoneinfo")
P("locale", "ロケール（BCP47 言語タグ。例 en-US, ja-JP）。", "string", "profile スコープ。互換のため en_US のような区切りを受理すべき場合あり。", pii="非該当", cmp="正規化が必要", vocab="標準で列挙（BCP47）", syn="G-locale")
P("phone_number", "希望する電話番号（E.164 推奨）。", "string", "phone スコープ。phone_number_verified=true なら E.164 形式 MUST。", syn="G-phone")
P("phone_number_verified", "phone_number が検証済みかどうか。", "boolean", "phone スコープ。true のとき phone_number は E.164 MUST。", writer="発行者（権威ある情報源）", syn="G-phone-verified")
P("address", "郵送先住所（JSON オブジェクト。§5.1.1 のメンバーを持つ）。", "object", "address スコープ。メンバーは formatted / street_address / locality / region / postal_code / country。", syn="G-address")
for sub, desc in [("formatted", "表示用に整形された完全な住所（改行を含み得る）。"),
                  ("street_address", "番地・建物名等（改行で複数行可）。"),
                  ("locality", "市区町村。"), ("region", "都道府県・州。"),
                  ("postal_code", "郵便番号。"), ("country", "国名（文字列。ISO コードとは限らない）。")]:
    R("address." + sub, "プロフィール・連絡先", desc, K_OIDF, "OpenID Connect Core 1.0 §5.1.1", CORE, "string", "両方",
      "address クレームのメンバー（トップレベルのクレームではない）。" + P_NOTE + VN,
      writer="本人が編集できる", mut="改名・変更あり", authz="不可（表示・監査用）", pii="直接識別できる個人情報",
      vocab="自由な文字列", uniq="なし", syn="G-address")
P("updated_at", "ユーザー情報が最後に更新された時刻。", NUM, "profile スコープ。", pii="非該当", writer="発行者（権威ある情報源）", mut="随時変わる", authz="補助のみ", syn="G-updated-at")

# =========================================================
# 4. Session / logout
# =========================================================
R("sid", "認証の強さ・セッション", "OP におけるユーザーエージェントのログインセッション識別子。RP 側のセッションとは別。",
  K_OIDF, "OpenID Connect Front-Channel Logout 1.0 §3（IANA 参照元）", FCL, "string", "ID",
  "Front-Channel / Back-Channel Logout で使用。発行者の文脈でのみ一意、RP には不透明。構文は client_id と同じ。Entra は ID/AT に sid（GUID）。Auth0 は sid を予約名としてカスタム設定不可。" + VN,
  sup="DUUUU", uniq="発行者内で一意", cmp="大小区別の完全一致", vocab="発行者ごと", pii="仮名の識別子", syn="G-session")
bs = "OpenID Connect Back-Channel Logout 1.0 §2.4"
for n, d, vt, extra in [("iss", "ログアウトトークンの発行者（OP）。", "string (URL)", "REQUIRED。"),
                        ("sub", "ログアウト対象のユーザー。sid と少なくともいずれかが必要。", "string", "OPTIONAL（sub か sid の少なくとも一方 MUST）。"),
                        ("aud", "ログアウトトークンの宛先 RP（client_id）。", "string または array of string", "REQUIRED。"),
                        ("iat", "ログアウトトークンの発行時刻。", NUM, "REQUIRED。"),
                        ("exp", "ログアウトトークンの有効期限。", NUM, "REQUIRED。"),
                        ("jti", "ログアウトトークンの一意 ID（リプレイ検出）。", "string", "REQUIRED。"),
                        ("sid", "ログアウト対象の OP セッション ID。", "string", "OPTIONAL（sub か sid の少なくとも一方 MUST）。")]:
    R(n, {"iss": "発行者・宛先", "aud": "発行者・宛先", "iat": "時刻・寿命", "exp": "時刻・寿命", "jti": "トークン種別・メタ",
          "sub": "識別子", "sid": "認証の強さ・セッション"}[n], d, K_OIDF, bs, BCL, vt, "ログアウトトークン",
      extra + "ID トークンとの取り違え防止のため typ=logout+jwt を推奨。" + VN,
      syn={"sub": "G-user-id", "sid": "G-session", "iss": "G-issuer", "aud": "G-audience"}.get(n, "G-" + n),
      cmp="大小区別の完全一致" if n in ("iss", "sub", "sid", "jti", "aud") else "該当なし",
      fresh="該当なし" if n in ("iat", "exp") else "発行時点で固定（寿命内は古いまま）")
R("events", "監査・相関・イベント", "ログアウトトークンであることを宣言する。メンバー名 http://schemas.openid.net/event/backchannel-logout を持つ JSON オブジェクト。",
  K_OIDF, bs, BCL, "object", "ログアウトトークン",
  "REQUIRED。メンバー値は JSON オブジェクトで空オブジェクト {} を推奨。RFC 8417 の SET の events を流用。" + VN,
  vocab="URI", syn="G-events")
R("nonce", "監査・相関・イベント", "ログアウトトークンに nonce を含めてはならない（ID トークンとの取り違え防止）。",
  K_OIDF, bs, BCL, "（禁止）", "ログアウトトークン", "MUST NOT be present。RP は nonce を含むログアウトトークンを拒否する。" + VN,
  fresh="該当なし", syn="G-nonce")

# =========================================================
# 5. RFC 7800 cnf and members, RFC 8705, RFC 9449
# =========================================================
R("cnf", "鍵・送信者制約", "JWT の提示者が保持を証明すべき鍵（Proof-of-Possession）を示す確認メソッドの入れ物。",
  K_RFC, "RFC 7800 §3.1", RFC(7800), "object", "両方",
  "メンバー jwk / jwe / kid / jku（RFC 7800）、x5t#S256（RFC 8705）、jkt（RFC 9449）。RFC 7800 は cnf を含む JWT に sub か iss を要求するが SD-JWT VC 草案 -27 はこの要件を外す。Auth0 は cnf を予約名としてカスタム設定不可。" + VN,
  authz="iss・aud などと組で可", syn="G-cnf")
for m, d, vt, src, url in [("jwk", "PoP 鍵そのもの（公開鍵 JWK）。", "object (JWK)", "RFC 7800 §3.2", RFC(7800)),
                           ("jwe", "暗号化された対称 PoP 鍵（JWE）。", "string (JWE compact) または object", "RFC 7800 §3.3", RFC(7800)),
                           ("kid", "PoP 鍵の鍵 ID（受け手が別途鍵を知っている前提）。", "string", "RFC 7800 §3.4", RFC(7800)),
                           ("jku", "PoP 鍵を含む JWK Set の URL（kid と併用）。", "string (URL)", "RFC 7800 §3.5", RFC(7800)),
                           ("x5t#S256", "mTLS クライアント証明書の SHA-256 サムプリント（証明書バウンド AT）。", "string (base64url)", "RFC 8705 §3.1", RFC(8705)),
                           ("jkt", "DPoP 公開鍵の JWK SHA-256 サムプリント（DPoP バウンド AT）。", "string (base64url)", "RFC 9449 §6.1", RFC(9449))]:
    R("cnf." + m, "鍵・送信者制約", d, K_RFC, src, url, vt, "AT" if m in ("x5t#S256", "jkt") else "両方",
      "cnf のメンバー（confirmation method）。リソースサーバーは提示時の TLS 証明書／DPoP 証明の鍵と一致を確認する。" + VN,
      writer="発行者が派生" if m in ("x5t#S256", "jkt") else "発行者（権威ある情報源）",
      cmp="大小区別の完全一致" if m in ("kid", "x5t#S256", "jkt") else "不明", syn="G-cnf")

s9449 = "RFC 9449 §4.2"
for n, d, vt, req in [("jti", "DPoP 証明 JWT の一意 ID。サーバーはリプレイ検出に使う。", "string", "REQUIRED。"),
                      ("htm", "DPoP 証明が付けられた HTTP リクエストのメソッド。", "string", "REQUIRED。"),
                      ("htu", "DPoP 証明が付けられた HTTP リクエストの URI（クエリ・フラグメント除く）。", "string (URI)", "REQUIRED。比較時は RFC 3986 の正規化が必要。"),
                      ("iat", "DPoP 証明の作成時刻。サーバーは許容時間窓で鮮度を判定。", NUM, "REQUIRED。"),
                      ("ath", "同時に提示するアクセストークン値の SHA-256 ハッシュ（base64url）。", "string (base64url)", "リソースアクセス時 REQUIRED。"),
                      ("nonce", "サーバーが DPoP-Nonce で供給した nonce 値。", "string", "サーバーが nonce を要求した場合に REQUIRED。IANA の nonce は OIDC Core と RFC 9449 を併記。")]:
    R(n, {"jti": "トークン種別・メタ", "iat": "時刻・寿命", "nonce": "監査・相関・イベント"}.get(n, "鍵・送信者制約"), d, K_RFC, s9449, RFC(9449), vt, "DPoP 証明",
      req + " DPoP 証明（typ=dpop+jwt、ヘッダーに jwk）専用でアクセストークンには入らない。htm/htu/ath は IANA で RFC 9449 §4.2 が登録元。" + VN,
      writer="呼び出し元・クライアントの申告",
      cmp={"htu": "正規化が必要", "htm": "大小区別の完全一致", "ath": "大小区別の完全一致", "jti": "大小区別の完全一致", "nonce": "大小区別の完全一致"}.get(n, "該当なし"),
      fresh="発行ごとに再計算", syn="G-dpop-" + n if n in ("htm", "htu", "ath") else "G-" + n)

# =========================================================
# 6. RFC 8693 token exchange claims
# =========================================================
R("act", "委任・行為者", "委任時に、主体（sub）に代わって実際に行為している主体（actor）を示す。ネストした act は過去の委任チェーンで、アクセス判断には現在の（最外の）actor のみを使う。",
  K_RFC, "RFC 8693 §4.1", RFC(8693), "object（sub などの識別クレームを持つ。ネスト可）", "AT",
  "act の中には sub/iss などの識別クレームを置き、exp/nbf/aud 等は置かない。ネストした act は情報提供のみで認可判断に使わない。Keycloak は Token exchange delegation（26.8 で preview）で act={sub, client_id}、Auth0 は On-Behalf-Of Token Exchange で act ネスト（深さ上限 4）、Cognito は actor token 付き token exchange（2026-11-12〜）で act。Entra Agent ID は act ではなく azp + xms_act_fct で表す。" + VN,
  sup="NCCUC", authz="iss・aud などと組で可", writer="発行者が派生", syn="G-actor")
R("act.sub", "委任・行為者", "actor の識別子。", K_RFC, "RFC 8693 §4.1", RFC(8693), "string", "AT",
  "act のメンバー。iss と組で解釈（act.iss がなければ外側の文脈）。Keycloak の例では act.client_id も入る。" + VN,
  sup="UCCUC", pii="仮名の識別子", cmp="大小区別の完全一致", uniq="発行者内で一意", syn="G-actor")
R("may_act", "委任・行為者", "その主体のために actor になることを許された相手を示す（トークン交換の認可判断材料）。実際に委任が起きたことは意味しない。",
  K_RFC, "RFC 8693 §4.4", RFC(8693), "object（sub 等の識別クレーム）", "AT",
  "subject_token に入れて、誰が actor_token として交換できるかを示す。Cognito は may_act を発行も評価もしないと明記。Keycloak 26.8 は may_act を使う制限ポリシー executor を追加（発行可否は未確認）。Auth0 は may_act を予約名としてカスタム設定不可。" + VN,
  sup="UUUUX", authz="補助のみ", syn="G-actor")
R("scope", "権限・認可", "トークンに結び付いたスコープ値（空白区切り）。OAuth の scope パラメータと同じ文法。",
  K_RFC, "RFC 8693 §4.2", RFC(8693), "string (space-delimited)", "AT",
  "大小区別のスコープトークンを空白区切り。Entra は scp（空白区切り文字列）、Okta は scp（配列）、Cognito AT は scope（空白区切り）を使う。" + VN,
  sup="NUUND", authz="iss・aud などと組で可", writer="発行者が派生", cmp="大小区別の完全一致", vocab="発行者ごと", syn="G-scope")
R("client_id", "クライアント・ワークロード", "トークンを要求した OAuth クライアントの識別子。",
  K_RFC, "RFC 8693 §4.3", RFC(8693), "string", "AT",
  "Entra は azp/appid、Okta は cid、Cognito AT は client_id（AT に aud がない代わりに検証対象）。Auth0 は RFC 9068 プロファイル選択時に client_id。" + VN,
  sup="NUCND", authz="iss・aud などと組で可", cmp="大小区別の完全一致", uniq="発行者内で一意", vocab="発行者ごと", syn="G-client-id")

# =========================================================
# 7. RFC 9068 JWT AT profile + RFC 7643 SCIM
# =========================================================
s9068 = "RFC 9068 §2.2"
for n, d, vt, req, cat, sup, syn in [
    ("iss", "AT の発行者（AS）。AS メタデータの issuer と一致。", "string (StringOrURI)", "REQUIRED。", "発行者・宛先", "DDDDD", "G-issuer"),
    ("exp", "AT の有効期限。", NUM, "REQUIRED。", "時刻・寿命", "DDDDD", "G-exp"),
    ("aud", "AT の宛先リソース（resource パラメータ等で決まる）。", "string または array of string", "REQUIRED。リソースサーバーは自分を示さない AT を拒否。", "発行者・宛先", "DCDDC", "G-audience"),
    ("sub", "リソース所有者（ユーザー）またはクライアント自身（client credentials 時）の識別子。", "string", "REQUIRED。AS はクライアントが sub に影響できないようにすべき（例: client credentials で client_id を sub に使うなら任意の client_id 登録を防ぐ。高権限ユーザーの sub を詐称されるため）。", "識別子", "DDDDD", "G-user-id"),
    ("client_id", "AT を要求したクライアント（RFC 8693 §4.3 の定義を使用）。", "string", "REQUIRED。", "クライアント・ワークロード", "NUCND", "G-client-id"),
    ("iat", "AT の発行時刻。", NUM, "REQUIRED。", "時刻・寿命", "DDDDD", "G-iat"),
    ("jti", "AT の一意 ID。", "string", "REQUIRED。", "トークン種別・メタ", "NUCUC", "G-jti"),
    ("auth_time", "ユーザーが最後に認証した時刻（OIDC の定義を流用）。", NUM, "OPTIONAL（§2.2.1）。", "認証の強さ・セッション", "UUUDD", "G-auth-time"),
    ("acr", "ユーザー認証の ACR（OIDC の定義を流用）。", "string", "OPTIONAL（§2.2.1）。", "認証の強さ・セッション", "DDUDD", "G-acr"),
    ("amr", "ユーザー認証方式（OIDC の定義を流用）。", "array of string", "OPTIONAL（§2.2.1）。", "認証の強さ・セッション", "CUUUD", "G-amr"),
    ("scope", "付与されたスコープ（RFC 8693 §4.2 の定義を使用）。", "string (space-delimited)", "要求に scope があれば SHOULD（§2.2.3）。", "権限・認可", "NUUND", "G-scope")]:
    R(n, cat, d, K_RFC, s9068 + (".1" if n in ("auth_time", "acr", "amr") else (".3" if n == "scope" else "")), RFC(9068), vt, "AT",
      req + " JWT AT はヘッダー typ=at+jwt（推奨 application/at+jwt）。Auth0 は RFC 9068 プロファイルを選べる（typ: at+jwt, client_id, jti）。" + VN,
      sup=sup, syn=syn, authz="iss・aud などと組で可" if n in ("iss", "aud", "sub", "client_id", "scope") else "補助のみ",
      fresh="該当なし" if vt == NUM else "発行時点で固定（寿命内は古いまま）",
      cmp="大小区別の完全一致" if n in ("iss", "aud", "sub", "client_id", "jti", "scope") else cmp_default(vt),
      pii="仮名の識別子" if n == "sub" else "非該当")
for n, d, supv, notes in [
    ("groups", "ユーザーが所属するグループ（SCIM groups 属性に対応）。", "CUHCN",
     "Entra は groupMembershipClaims で有効化、JWT で 200 件超は欠落し _claim_names に置換（hasgroups 等）。Okta は group filter 設定、上限 100 で超過時リクエスト失敗。Cognito は cognito:groups。Auth0 は groups を素の名前で追加不可（namespaced クレームを Action で）。Keycloak は Group Membership mapper（未検証）。"),
    ("roles", "ユーザーのロール（SCIM roles 属性に対応）。", "DNHUN",
     "Entra は roles（アプリロール割当時）。Keycloak は realm_access.roles / resource_access.<client>.roles。Auth0 は roles を素の名前で追加不可（namespaced で自作）。Cognito の cognito:roles は IAM ロール ARN で意味が異なる。"),
    ("entitlements", "ユーザーの権利（SCIM entitlements 属性に対応）。", "UUNUU",
     "Auth0 は RBAC 有効化 + 「Add Permissions in the Access Token」で permissions（概念は近いが別名・別定義）。他 IdP の対応は未確認。")]:
    R(n, "権限・認可", d + "値の語彙は AS が決める。", K_RFC, "RFC 9068 §2.2.3.1", RFC(9068), "array of string", "AT",
      "RFC 9068 は SCIM（RFC 7643 §4.1.2）の属性名を JWT クレームとして使う。IANA 参照は RFC 7643 と RFC 9068 の併記。" + notes + " " + VN,
      sup=supv, authz="補助のみ", vocab="発行者ごと", cmp="大小区別の完全一致",
      limit="Entra: groups は JWT 200 件超で欠落（overage）。Okta: groups 100 件超でリクエスト失敗" if n == "groups" else "記載なし",
      mut="随時変わる", syn="G-" + n)
    R(n, "権限・認可", "SCIM の User 属性（グループ / ロール / 権利）。SCIM ではそれぞれ value・display・type・primary を持つ複数値属性。", K_RFC,
      "RFC 7643 §4.1.2", RFC(7643), "array of object（SCIM multi-valued attribute）", "その他（SCIM リソース属性。JWT では RFC 9068 が文字列配列として使用）",
      "RFC 7643 では JWT クレームではなく SCIM スキーマの属性（groups は読み取り専用で Group リソース側で管理）。同節には x509Certificates もあるが JWT クレームとしては未登録。IANA の roles/groups/entitlements 登録は本 RFC と RFC 9068 を参照。" + VN,
      authz="補助のみ", vocab="発行者ごと", mut="随時変わる", cmp="不明", syn="G-" + n)

# =========================================================
# 8. RFC 8417 SET, RFC 9493, SSF/CAEP/RISC
# =========================================================
R("events", "監査・相関・イベント", "SET（Security Event Token）が表すセキュリティイベント。キーがイベント種別 URI、値がイベント固有の JSON オブジェクト。",
  K_RFC, "RFC 8417 §2.2", RFC(8417), "object", "SET",
  "REQUIRED（SET では）。SET は typ=secevent+jwt を推奨し、ID トークン・AT との取り違えを防ぐため sub/exp の扱いに注意（§4）。" + VN, vocab="URI", syn="G-events")
R("toe", "監査・相関・イベント", "イベントが発生した時刻（SET の発行時刻 iat とは別）。", K_RFC, "RFC 8417 §2.2", RFC(8417), NUM, "SET",
  "OPTIONAL。CAEP は代わりにイベント内メンバー event_timestamp を使う。" + VN, fresh="該当なし", syn="G-event-time")
R("txn", "監査・相関・イベント", "複数の SET（や関連処理）を一つの取引に関連付ける一意の取引識別子。", K_RFC, "RFC 8417 §2.2", RFC(8417), "string", "SET",
  "OPTIONAL。発行者の文脈で一意。Transaction Tokens 草案も txn を流用。" + VN, cmp="大小区別の完全一致", uniq="発行者内で一意", syn="G-txn")
R("sub_id", "識別子", "Subject Identifier（format メンバーで形式を示す JSON オブジェクト）により主体を表す。sub の代替。",
  K_RFC, "RFC 9493 §4.1", RFC(9493), "object", "SET",
  "形式（Security Event Identifier Formats レジストリ）: account, email, iss_sub, opaque, phone_number, did, uri, aliases。SSF の SET は sub を使わず sub_id を使う。" + VN,
  pii="仮名の識別子", vocab="標準で列挙（Security Event Identifier Formats レジストリ）", syn="G-user-id")
sssf = "OpenID Shared Signals Framework 1.0"
R("sub_id", "識別子", "SSF の SET で主体（ユーザー・セッション・デバイス・テナント等）を表す Subject Identifier。complex 形式で複数主体の組を表せる。",
  K_OIDF, sssf + " §3 / §4.1.2", SSF, "object", "SET",
  "SSF は sub を MUST NOT とし sub_id を使う。追加形式 jwt_id（iss+jti）、saml_assertion_id、ip-addresses、complex（user/device/session/tenant 等）。2025-08 Final。" + VN,
  pii="仮名の識別子", vocab="標準で列挙（RFC 9493 + SSF §3.5）", syn="G-user-id")
R("txn", "監査・相関・イベント", "同じ取引に起因する SET 群を関連付ける取引 ID（RFC 8417 の定義）。", K_OIDF, sssf + " §4.1.9", SSF, "string", "SET",
  "Transmitter は txn を設定 SHOULD。" + VN, cmp="大小区別の完全一致", syn="G-txn")
R("events", "監査・相関・イベント", "SSF の SET が運ぶイベント（CAEP / RISC / SSF のイベント種別 URI をキーとする）。", K_OIDF, sssf + " §4", SSF, "object", "SET",
  "SSF 自身のイベント: https://schemas.openid.net/secevent/ssf/event-type/verification, .../stream-updated。typ=secevent+jwt MUST、exp MUST NOT、sub MUST NOT。" + VN,
  vocab="URI", syn="G-events")
scaep = "OpenID Continuous Access Evaluation Profile 1.0"
for n, d, vt, voc in [("event_timestamp", "イベントが発生した時刻（イベントオブジェクト内）。", NUM, "該当なし"),
                      ("initiating_entity", "イベントを引き起こした主体の種別。", "string", "標準で列挙（admin, user, policy, system）"),
                      ("reason_admin", "管理者向けのログ・監査用理由メッセージ（言語タグをキーとするオブジェクト）。", "object", "自由な文字列"),
                      ("reason_user", "エンドユーザー表示用の理由メッセージ（言語タグをキー）。", "object", "自由な文字列")]:
    R("events.<caep-event>." + n, "監査・相関・イベント", d, K_OIDF, scaep + " §2", CAEP, vt, "SET",
      "全 CAEP イベント共通の OPTIONAL メンバー（トップレベルのクレームではなく events の各イベント内）。2025-08 Final。" + VN,
      vocab=voc, fresh="該当なし" if vt == NUM else "発行時点で固定（寿命内は古いまま）", syn="G-caep-" + n.replace("_", "-"))
for ev, d, mem in [("session-revoked", "セッションが失効したことを通知する。", "固有メンバーなし（共通のみ）"),
                   ("token-claims-change", "トークンのクレーム値が変わったことを通知する。", "claims（変更後のクレーム）"),
                   ("credential-change", "資格情報の作成・失効・更新・削除を通知する。", "credential_type, change_type, friendly_name, x509_issuer, x509_serial, fido2_aaguid"),
                   ("assurance-level-change", "認証の保証レベルの変化を通知する。", "namespace, current_level, previous_level, change_direction"),
                   ("device-compliance-change", "デバイスのコンプライアンス状態の変化を通知する。", "current_status, previous_status"),
                   ("session-established", "新しいセッションの確立を通知する。", "fp_ua, acr, amr, ext_id"),
                   ("session-presented", "既存セッションが提示されたことを通知する。", "fp_ua, ext_id"),
                   ("risk-level-change", "主体のリスクレベル変化を通知する。", "risk_reason, principal, current_level, previous_level")]:
    R("events.https://schemas.openid.net/secevent/caep/event-type/" + ev, "監査・相関・イベント", d, K_OIDF, scaep + " §3", CAEP, "object", "SET",
      "events のキー（イベント種別 URI）。イベント固有メンバー: " + mem + "（名称は §3 の目次・例から確認、型の詳細は仕様参照）。" + VN,
      vocab="URI", syn="G-caep-event")
R("events.https://schemas.openid.net/secevent/risc/event-type/*", "監査・相関・イベント",
  "アカウントのセキュリティ状態（侵害・無効化・識別子変更など）を通知する RISC イベント群。", K_OIDF, "OpenID RISC Profile Specification 1.0", RISC, "object", "SET",
  "種別: account-credential-change-required, account-purged, account-disabled, account-enabled, identifier-changed, identifier-recycled, credential-compromise, opt-in, opt-out-initiated, opt-out-cancelled, opt-out-effective, recovery-activated, recovery-information-changed, sessions-revoked（14 種、1 行に集約）。2025-08 Final。" + VN,
  vocab="URI", syn="G-risc-event")

# =========================================================
# 9. RFC 9396 RAR
# =========================================================
R("authorization_details", "権限・認可", "トークンが表す細粒度の権限（type ごとの JSON オブジェクトの配列）。", K_RFC, "RFC 9396 §9.1", RFC(9396), "array of object", "AT",
  "JWT AT とイントロスペクション応答で使用。各要素は type 必須、他の共通メンバーは任意で type ごとに意味を定義。Auth0 の Asynchronous Authorization（CIBA+RAR）が RAR を使用（AT 内の表現は未確認）。" + VN,
  authz="iss・aud などと組で可", vocab="発行者ごと", syn="G-authz-details")
for m, d, vt in [("type", "権限の種類の識別子（他メンバーの意味を決める）。", "string"),
                 ("locations", "アクセス先リソース・リソースサーバーの URI の配列。", "array of string (URI)"),
                 ("actions", "リソースに対して行う操作の種類の配列。", "array of string"),
                 ("datatypes", "アクセスするデータの種類の配列。", "array of string"),
                 ("identifier", "特定のリソースの識別子。", "string"),
                 ("privileges", "要求する権限レベルの配列。", "array of string")]:
    R("authorization_details." + m, "権限・認可", d, K_RFC, "RFC 9396 §2 / §2.2", RFC(9396), vt, "AT",
      ("REQUIRED。" if m == "type" else "OPTIONAL。") + "authorization_details 各要素の共通メンバー（トップレベルのクレームではない）。" + VN,
      vocab="URI" if m == "locations" else "発行者ごと", cmp="大小区別の完全一致" if m == "type" else "不明", syn="G-authz-details")

# =========================================================
# 10. SD-JWT (RFC 9901), SD-JWT VC (draft-27), Token Status List (draft-21)
# =========================================================
R("_sd", "開示・暗号・検証補助", "オブジェクトのプロパティを選択的開示にするための Disclosure ダイジェストの配列。", K_RFC, "RFC 9901 §4.2.4.1", RFC(9901), "array of string", "証明書・VC",
  "検証者は受け取った Disclosure をハッシュして照合し、元のクレームを復元する。ダミーダイジェストも入り得る。" + VN, writer="発行者が派生", syn="G-sd")
R("...", "開示・暗号・検証補助", "配列要素を選択的開示にするためのダイジェスト（{\"...\": \"<digest>\"} の形で配列内に置く）。", K_RFC, "RFC 9901 §4.2.4.2", RFC(9901), "string（配列要素オブジェクトのキー）", "証明書・VC",
  "IANA 登録名は「...」（3 つのピリオド）。" + VN, writer="発行者が派生", syn="G-sd")
R("_sd_alg", "開示・暗号・検証補助", "Disclosure ダイジェストに使ったハッシュアルゴリズム（例 sha-256）。", K_RFC, "RFC 9901 §4.1.1", RFC(9901), "string", "証明書・VC",
  "省略時は sha-256。IANA Named Information Hash Algorithm レジストリの名前。" + VN, vocab="標準で列挙（IANA Named Information Hash Algorithm Registry）", syn="G-sd")
R("sd_hash", "開示・暗号・検証補助", "KB-JWT が結び付く SD-JWT（発行者署名 JWT + 提示する Disclosure）のダイジェスト。", K_RFC, "RFC 9901 §4.3", RFC(9901), "string (base64url)", "その他（KB-JWT）",
  "Key Binding JWT（typ=kb+jwt）で REQUIRED。KB-JWT は iat, aud, nonce, sd_hash を持つ。" + VN, writer="呼び出し元・クライアントの申告", fresh="発行ごとに再計算", cmp="大小区別の完全一致", syn="G-sd")
for n, d in [("iat", "KB-JWT の作成時刻。"), ("aud", "KB-JWT の宛先（検証者）。"), ("nonce", "検証者が提供した鮮度確保用の値。")]:
    R(n, {"iat": "時刻・寿命", "aud": "発行者・宛先", "nonce": "監査・相関・イベント"}[n], d, K_RFC, "RFC 9901 §4.3", RFC(9901),
      NUM if n == "iat" else "string", "その他（KB-JWT）", "KB-JWT で REQUIRED。保有者（Holder）が提示ごとに作る。" + VN,
      writer="呼び出し元・クライアントの申告", fresh="発行ごとに再計算", syn="G-" + ("audience" if n == "aud" else n))
R("cnf", "鍵・送信者制約", "SD-JWT の保有者鍵（Key Binding に使う鍵）。", K_RFC, "RFC 9901 §4.1.2", RFC(9901), "object", "証明書・VC",
  "Key Binding を使う場合、発行者署名 JWT に cnf（RFC 7800）で保有者公開鍵を入れる。" + VN, syn="G-cnf")
svc = "draft-ietf-oauth-sd-jwt-vc-27 §2.2.2"
for n, d, vt, req, disc in [
    ("iss", "VC の発行者（x5c 等で別途示されない場合）。", "string (StringOrURI)", "OPTIONAL。", "選択的開示不可"),
    ("nbf", "この時刻前は VC を受理しない。", NUM, "OPTIONAL。", "選択的開示不可"),
    ("exp", "VC の有効期限。", NUM, "OPTIONAL。", "選択的開示不可"),
    ("cnf", "保有者の鍵（Key Binding 用）。", "object", "Key Binding をサポートする場合 REQUIRED（JWK 推奨）。RFC 7800 の sub/iss 必須要件を本仕様で無効化。", "選択的開示不可"),
    ("vct", "VC の種類（Verifiable Digital Credential Type）の識別子（例 https://credentials.example.com/identity_credential）。", "string", "REQUIRED。Type Metadata の取得キー。", "選択的開示不可"),
    ("vct#integrity", "vct が指す Type Metadata 文書のハッシュ（integrity metadata）。", "string", "OPTIONAL。", "選択的開示不可"),
    ("aka_vcts", "VC の追加の種類識別子の配列。", "array of string", "OPTIONAL。", "選択的開示不可"),
    ("status", "VC の状態（失効等）の参照先。Token Status List を使う場合は Status List Token が JWT 形式。", "object", "OPTIONAL。", "選択的開示不可"),
    ("sub", "VC の主体の識別子（発行者が知る値）。cnf との結び付きは要求されない。", "string", "OPTIONAL。", "選択的開示可"),
    ("iat", "VC の発行時刻。", NUM, "OPTIONAL。", "選択的開示可")]:
    R(n, {"iss": "発行者・宛先", "nbf": "時刻・寿命", "exp": "時刻・寿命", "iat": "時刻・寿命", "cnf": "鍵・送信者制約", "vct": "トークン種別・メタ",
          "vct#integrity": "開示・暗号・検証補助", "aka_vcts": "トークン種別・メタ", "status": "トークン種別・メタ", "sub": "識別子"}[n],
      d, K_DRAFT, svc, SDVC, vt, "証明書・VC",
      req + disc + "。草案 -27（2026-11-16）。typ=dc+sd-jwt。vct / vct#integrity / aka_vcts は IANA 登録申請中（現行 IANA 一覧には未掲載）。" + VN,
      status="草案（-27）", cc="IETF", syn={"iss": "G-issuer", "sub": "G-user-id"}.get(n, "G-" + n.replace("#", "-")),
      fresh="該当なし" if vt == NUM else "発行時点で固定（寿命内は古いまま）",
      vocab="URI" if n == "vct" else ("該当なし" if vt == NUM else "不明"),
      cmp="大小区別の完全一致" if n in ("vct", "iss") else cmp_default(vt), pii="仮名の識別子" if n == "sub" else "非該当")
stsl = "draft-ietf-oauth-status-list-21"
R("status", "トークン種別・メタ", "参照トークン（Referenced Token）の状態確認方法の参照（status mechanism）を含むオブジェクト。", K_DRAFT, stsl + " §6.1", TSL, "object", "その他（Referenced Token：SD-JWT VC、JWT 等）",
  "REQUIRED（Referenced Token で）。IANA は RFC-ietf-oauth-status-list-21 として登録済み（RFC 番号未付与）。草案 -21（2026-06-21）。" + VN,
  status="草案（-21、RFC 編集待ち）", cc="IETF", syn="G-status", fresh="都度照会が必要")
for m, d, vt in [("idx", "Status List 内でこのトークンの状態を示すインデックス（非負整数）。", "integer"),
                 ("uri", "状態情報を含む Status List Token の URI。", "string (URI)")]:
    R("status.status_list." + m, "トークン種別・メタ", d, K_DRAFT, stsl + " §6.1", TSL, vt, "その他（Referenced Token）",
      "status.status_list のメンバー（REQUIRED）。" + VN, status="草案（-21）", cc="IETF", syn="G-status",
      vocab="URI" if m == "uri" else "該当なし", cmp="大小区別の完全一致" if m == "uri" else "該当なし")
R("status_list", "トークン種別・メタ", "多数のトークンの最新状態をビット列で保持する Status List（Status List Token の中身）。", K_DRAFT, stsl + " §5.1", TSL, "object", "その他（Status List Token, typ=statuslist+jwt）",
  "REQUIRED（Status List Token で）。状態値 0x00 VALID / 0x01 INVALID / 0x02 SUSPENDED ほか。" + VN, status="草案（-21、RFC 編集待ち）", cc="IETF", syn="G-status", fresh="都度照会が必要")
for m, d, vt in [("bits", "1 トークンあたりのビット数（1/2/4/8）。", "integer"),
                 ("lst", "状態値のバイト列（DEFLATE 圧縮して base64url）。", "string (base64url)"),
                 ("aggregation_uri", "Status List Aggregation への URI。", "string (URI)")]:
    R("status_list." + m, "トークン種別・メタ", d, K_DRAFT, stsl + " §4.2", TSL, vt, "その他（Status List Token）",
      ("REQUIRED。" if m != "aggregation_uri" else "OPTIONAL。") + "status_list のメンバー。" + VN, status="草案（-21）", cc="IETF", syn="G-status",
      vocab="標準で列挙（1, 2, 4, 8）" if m == "bits" else ("URI" if m == "aggregation_uri" else "不明"))
R("ttl", "時刻・寿命", "Status List Token をキャッシュしてよい最大秒数。", K_DRAFT, stsl + " §5.1", TSL, "number (秒、正の数)", "その他（Status List Token）",
  "RECOMMENDED。exp とは別に再取得の目安を示す。" + VN, status="草案（-21、RFC 編集待ち）", cc="IETF", fresh="該当なし", syn="G-ttl")
R("sub", "識別子", "Status List Token の URI（Referenced Token の status_list.uri と同値）。", K_DRAFT, stsl + " §5.1", TSL, "string (URI)", "その他（Status List Token）",
  "REQUIRED。ユーザーではなくリスト自体を指す点で通常の sub と意味が異なる。iat REQUIRED、exp RECOMMENDED。" + VN,
  status="草案（-21）", cc="IETF", vocab="URI", cmp="大小区別の完全一致", syn="G-status")

# =========================================================
# 11. Transaction Tokens draft-11
# =========================================================
stx = "draft-ietf-oauth-transaction-tokens-11 §9.2"
for n, d, vt, req, cat, syn in [
    ("iss", "Txn-Token の発行者（TTS）。単一 Trust Domain に閉じるため必須ではない。", "string", "OPTIONAL。", "発行者・宛先", "G-issuer"),
    ("iat", "Txn-Token の発行時刻。", NUM, "REQUIRED。", "時刻・寿命", "G-iat"),
    ("aud", "Txn-Token が有効な Trust Domain。その外では受理してはならない。", "string", "REQUIRED。", "発行者・宛先", "G-audience"),
    ("exp", "Txn-Token の有効期限（短寿命）。", NUM, "REQUIRED。", "時刻・寿命", "G-exp"),
    ("txn", "取引の一意識別子（RFC 8417 §2.2 の定義）。", "string", "REQUIRED。", "監査・相関・イベント", "G-txn"),
    ("sub", "取引の主体。aud の Trust Domain 内で一意。OIDC と異なり iss とは結び付かない。", "string", "REQUIRED。", "識別子", "G-user-id"),
    ("scope", "この取引の目的を可能な限り狭く表すスコープ（TTS が決定、外部トークンの scope と一致する必要はない）。", "string", "REQUIRED。", "権限・認可", "G-scope"),
    ("tctx", "呼び出しチェーン全体で不変の取引コンテキスト（TTS が決める認可詳細。例 action, ticker, quantity）。", "object", "RECOMMENDED。IANA 登録申請（Transaction authorization details）。", "同意・目的・取引", "G-txn-context"),
    ("rctx", "要求の環境コンテキスト（例 req_ip, authn, 要求したエンティティ）。", "object", "RECOMMENDED。IANA 登録申請（requester context）。", "端末・ネットワーク・場所", "G-request-context"),
    ("req_wl", "Txn-Token を要求したワークロードの識別子。", "string", "REQUIRED。", "クライアント・ワークロード", "G-workload")]:
    R(n, cat, d, K_DRAFT, stx, TXN, vt, "Txn-Token",
      req + " 草案 -11（2026-07、有効期限 2027-01-31）。ヘッダー typ=txntoken+jwt MUST。受け手は理解しないクレームを無視 MUST。ベンダー提供は未確認。",
      status="草案（-11）", cc="IETF", writer="発行者が派生" if n in ("scope", "tctx", "rctx", "sub") else "発行者（権威ある情報源）",
      fresh="該当なし" if vt == NUM else "発行時点で固定（寿命内は古いまま）",
      uniq="発行者内で一意" if n in ("txn", "sub") else "該当なし", pii="仮名の識別子" if n == "sub" else ("不明" if n == "rctx" else "非該当"),
      cmp="大小区別の完全一致" if vt == "string" else cmp_default(vt), syn=syn)

# =========================================================
# 12. ID-JAG draft-06
# =========================================================
sj = "draft-ietf-oauth-identity-assertion-authz-grant-06 §3.1"
for n, d, vt, req, cat, syn in [
    ("iss", "ID-JAG を発行した IdP 認可サーバーの issuer。", "string (URL)", "REQUIRED。", "発行者・宛先", "G-issuer"),
    ("sub", "IdP がリソース AS 向けに選んだユーザー識別子（iss+sub、マルチテナントは iss+tenant+sub で一意）。", "string", "REQUIRED。", "識別子", "G-user-id"),
    ("sub_id", "異なる名前空間（例 SAML NameID）でのユーザー識別子（RFC 9493）。sub と同一ユーザーを指す。", "object", "OPTIONAL。saml-nameid 形式を本草案で登録。", "識別子", "G-user-id"),
    ("aud", "リソース認可サーバーの issuer 識別子。", "string (URL)", "REQUIRED。", "発行者・宛先", "G-audience"),
    ("client_id", "リソース AS におけるクライアント ID（IdP での client_id と異なり得る）。", "string", "REQUIRED。", "クライアント・ワークロード", "G-client-id"),
    ("jti", "ID-JAG の一意 ID。", "string", "REQUIRED。", "トークン種別・メタ", "G-jti"),
    ("exp", "有効期限。", NUM, "REQUIRED。", "時刻・寿命", "G-exp"),
    ("iat", "発行時刻。", NUM, "REQUIRED。", "時刻・寿命", "G-iat"),
    ("resource", "アクセスを許す保護リソース（RFC 8707 のリソース識別子）。単一なら文字列、複数なら一意な文字列の配列。", "string または array of string (URI)", "OPTIONAL。本草案で IANA に resource クレームを登録申請。", "発行者・宛先", "G-resource"),
    ("scope", "トークンに結び付くスコープ（空白区切り）。", "string (space-delimited)", "OPTIONAL。", "権限・認可", "G-scope"),
    ("authorization_details", "RAR（RFC 9396）の権限詳細。", "array of object", "OPTIONAL。", "権限・認可", "G-authz-details"),
    ("act", "sub に代わって行為する actor（RFC 8693 §4.1）。", "object", "OPTIONAL。", "委任・行為者", "G-actor"),
    ("tenant", "マルチテナント発行者のテナント識別子（OpenID.Enterprise の定義）。", "string", "OPTIONAL。", "組織・テナント", "G-tenant"),
    ("auth_time", "ユーザーの認証時刻（OIDC Core）。", NUM, "OPTIONAL。", "認証の強さ・セッション", "G-auth-time"),
    ("acr", "ユーザー認証が満たした ACR（OIDC Core）。", "string", "OPTIONAL。", "認証の強さ・セッション", "G-acr"),
    ("amr", "ユーザー認証方式（OIDC Core）。", "array of string", "OPTIONAL。", "認証の強さ・セッション", "G-amr"),
    ("aud_tenant", "リソース AS 側のテナント識別子（リソース AS がマルチテナントで IdP が知る場合のみ）。", "string", "OPTIONAL。本草案で IANA 登録申請。aud+aud_tenant+aud_sub はリソース AS 内で一意 MUST。", "組織・テナント", "G-tenant"),
    ("aud_sub", "リソース AS 側でのユーザー識別子（OpenID.Enterprise の定義）。", "string", "OPTIONAL。", "識別子", "G-user-id"),
    ("email", "ユーザーのメールアドレス（OIDC Core §5.1）。", "string", "OPTIONAL。", "プロフィール・連絡先", "G-email")]:
    R(n, cat, d, K_DRAFT, sj, IDJAG, vt, "その他（ID-JAG：JWT 認可グラント）",
      req + " 草案 -06（2026-10-31、有効期限 2027-05-04）。ヘッダー typ=oauth-id-jag+jwt MUST。ID-JAG は IdP AS がトークン交換で発行し、クライアントがリソース AS に jwt-bearer グラントとして提示。Okta は Cross App Access（XAA）で ID-JAG を実装、Keycloak 26.7 は Identity Assertion JWT Grant（experimental）。各クレームの IdP 別出力は未確認。",
      sup="UUUUU", status="草案（-06）", cc="IETF",
      fresh="該当なし" if vt == NUM else "発行時点で固定（寿命内は古いまま）",
      pii="直接識別できる個人情報" if n == "email" else ("仮名の識別子" if n in ("sub", "sub_id", "aud_sub") else "非該当"),
      cmp="大小区別の完全一致" if n in ("iss", "sub", "aud", "client_id", "jti", "tenant", "aud_tenant", "aud_sub") else cmp_default(vt),
      uniq="発行者内で一意" if n in ("sub", "jti") else "該当なし", syn=syn)
R("requested_cnf", "鍵・送信者制約", "信頼ドメイン A のクライアント鍵（cnf）をドメイン B の AS に伝え、発行 AT の cnf に引き継がせるための値（例として言及）。",
  K_DRAFT, "draft-ietf-oauth-identity-chaining-17 Appendix（sender constraining）", CHAIN, "object（cnf と同形）", "その他（JWT 認可グラント）",
  "草案 -17（2026-07-19）。本文は「例えば requested_cnf クレームを含めることで実現できる」と言及するのみで、IANA 登録や正式定義はない。Identity chaining 草案自体は新しいクレームを定義せず、クレームの転記（transcription）を扱う。",
  status="草案（-17）", cc="IETF", writer="発行者が派生", verified=True, syn="G-cnf")

# =========================================================
# 13. OpenID Identity Assurance
# =========================================================
sida = "OpenID Identity Assurance Schema Definition 1.0"
R("verified_claims", "本人確認・保証", "検証済みのユーザークレーム（claims）と、その検証の方法・根拠（verification）を一組にした入れ物。未検証クレームと混同させないための構造。",
  K_OIDF, sida + " §5", IDAS, "object または array of object", "両方",
  "2024-10-01 Final。複数の verified_claims を配列で持てる。実装は未定義のサブ要素を無視 MUST。" + VN,
  pii="機微な個人情報", authz="補助のみ", syn="G-verified-claims")
R("verified_claims.claims", "本人確認・保証", "verification で検証されたユーザークレーム（name, given_name, family_name, birthdate, address、IDA Claims Registration のクレーム等）。",
  K_OIDF, sida + " §5.3", IDAS, "object", "両方", "空オブジェクト可（検証の事実のみ共有する場合）。" + VN, pii="直接識別できる個人情報", syn="G-verified-claims")
R("verified_claims.verification", "本人確認・保証", "本人確認プロセスとアカウントへの紐付けに関する情報。", K_OIDF, sida + " §5.4.2", IDAS, "object", "両方",
  "OIDC 以外（W3C VC 等）でも単独で使える。" + VN, syn="G-verified-claims")
for m, d, vt, req, voc in [
    ("trust_framework", "本人確認を規律するトラストフレームワーク（例 de_aml, eidas）。", "string", "Required。", "標準で列挙（OIDF IDA predefined values ページ）"),
    ("assurance_level", "クレームの保証レベル（値域は trust_framework に依存。例 eidas: low/substantial/high）。", "string", "Optional。", "発行者ごと"),
    ("assurance_process", "従った保証プロセス（policy, procedure, assurance_details 等）。", "object", "Optional。", "発行者ごと"),
    ("time", "本人確認プロセスが完了した日時（ISO 8601）。", "string (ISO 8601 date-time)", "Optional（フレームワークにより必須）。", "該当なし"),
    ("verification_process", "本人確認プロセスの一意参照（紛争・監査時の照会用）。", "string", "Optional（フレームワークにより必須）。", "発行者ごと"),
    ("evidence", "本人確認に使った証拠の配列（type で種類を示す）。", "array of object", "Optional。", "発行者ごと")]:
    R("verified_claims.verification." + m, "本人確認・保証", d, K_OIDF, sida + " §5.4.2", IDAS, vt, "両方", req + VN,
      vocab=voc, pii="機微な個人情報" if m == "evidence" else "非該当", syn="G-verified-claims")
R("verified_claims.verification.evidence.type", "本人確認・保証", "証拠の種類。", K_OIDF, sida + " §5.4.4.1", IDAS, "string", "両方",
  "Required。document / electronic_record / vouch / electronic_signature。種類ごとに check_details, document_details, derived_claims 等の追加要素。" + VN,
  vocab="標準で列挙（document, electronic_record, vouch, electronic_signature）", syn="G-verified-claims")
R("verified_claims.verification.evidence.attachments", "本人確認・保証", "書類の写し等の添付（埋め込みまたは外部参照）。", K_OIDF, sida + " §5.4.4.1 / §5.4.5", IDAS, "array of object", "両方",
  "Optional。トークンサイズと個人情報量に注意。" + VN, pii="機微な個人情報", syn="G-verified-claims")
sidc = "OpenID Connect for Identity Assurance Claims Registration 1.0 §4"
for n, d, vt, pii, voc in [
    ("place_of_birth", "出生地（locality / region / country のメンバーを持つ）。", "object", "直接識別できる個人情報", "不明"),
    ("nationalities", "国籍の配列。", "array of string", "機微な個人情報", "標準で列挙（ISO 3166 国コード）"),
    ("birth_family_name", "出生時（または幼少時から）の姓。", "string", "直接識別できる個人情報", "自由な文字列"),
    ("birth_given_name", "出生時（または幼少時から）の名。", "string", "直接識別できる個人情報", "自由な文字列"),
    ("birth_middle_name", "出生時（または幼少時から）のミドルネーム。", "string", "直接識別できる個人情報", "自由な文字列"),
    ("salutation", "敬称（例 Mr）。", "string", "直接識別できる個人情報", "自由な文字列"),
    ("title", "肩書（例 Dr）。", "string", "直接識別できる個人情報", "自由な文字列"),
    ("msisdn", "ITU-T E.164 形式の携帯電話番号。", "string", "直接識別できる個人情報", "自由な文字列"),
    ("also_known_as", "芸名・宗教名など法的氏名以外の別名。", "string", "直接識別できる個人情報", "自由な文字列")]:
    R(n, "本人確認・保証" if n in ("place_of_birth", "nationalities") else "プロフィール・連絡先", d, K_OIDF, sidc, IDAC, vt, "両方",
      "2024-10-01 Final。verified_claims.claims 内でも、単独のクレームとしても使える。" + VN,
      pii=pii, vocab=voc, writer="発行者（権威ある情報源）", mut="改名・変更あり" if n in ("salutation", "title", "msisdn", "also_known_as") else "不明",
      syn="G-name" if n.startswith("birth_") else "G-" + n.replace("_", "-"))
R("place_of_birth.locality", "本人確認・保証", "出生地の市区町村。", K_OIDF, sidc, IDAC, "string", "両方", "place_of_birth のメンバー（country / region と並ぶ）。" + VN, pii="直接識別できる個人情報", syn="G-place-of-birth")

# =========================================================
# 14. RFC 9200 ACE, RFC 9701, RFC 9321, RFC 9560, RFC 8485
# =========================================================
R("ace_profile", "トークン種別・メタ", "トークンを使う ACE プロファイル（例 DTLS / OSCORE プロファイル）。", K_RFC, "RFC 9200 §5.10", RFC(9200), "string", "AT",
  "IoT 向け ACE-OAuth（制約デバイス）専用。CWT でも使う。IANA の変更管理者は IETF。" + VN, cc="IETF", vocab="標準で列挙（ACE Profile レジストリ）", syn="G-ace")
R("cnonce", "時刻・寿命", "RS がクライアント経由で AS に渡した nonce。時計同期できない RS がトークンの鮮度を確認する。", K_RFC, "RFC 9200 §5.10", RFC(9200), "string (byte string)", "AT",
  "IoT 向け ACE-OAuth 専用。" + VN, cc="IETF", writer="呼び出し元・クライアントの申告", syn="G-nonce")
R("exi", "時刻・寿命", "RS が初めてトークンを見た時点からの寿命（秒）。時計を持たないデバイス向けの弱い期限。", K_RFC, "RFC 9200 §5.10.3", RFC(9200), "number (秒)", "AT",
  "IoT 向け ACE-OAuth 専用。RS は使用済みトークンの記録が必要。" + VN, cc="IETF", fresh="該当なし", syn="G-exp")
R("token_introspection", "トークン種別・メタ", "JWT 形式のイントロスペクション応答で、RFC 7662 の応答メンバー（active, scope, sub 等）を収める入れ物。", K_RFC, "RFC 9701 §5", RFC(9701), "object", "その他（JWT イントロスペクション応答 typ=token-introspection+jwt）",
  "非アクティブなら active=false のみ。メンバーをトップレベルと分けるのは衝突防止のため。2025-01 RFC。" + VN, cc="IETF", fresh="発行ごとに再計算", syn="G-introspection")
R("sig_val_claims", "開示・暗号・検証補助", "電子署名の検証結果を記録する Signature Validation Token（SVT）の検証クレーム群。", K_RFC, "RFC 9321 §3.2.3", RFC(9321), "array of object (SigValidation)", "その他（SVT）",
  "RFC 9321 は Independent Submission（Informational）であり IETF 標準トラックではない。電子署名の長期検証用途。" + VN, cc="IETF", syn="G-sig-validation")
R("rdap_allowed_purposes", "同意・目的・取引", "RDAP（登録データアクセス）で利用可能な照会目的の集合。", K_RFC, "RFC 9560 §3.1.5.1", RFC(9560), "array of string", "ID",
  "RDAP の連携認証専用。値は RDAP Query Purpose レジストリ。" + VN, cc="IETF", vocab="標準で列挙（RDAP Query Purpose Values レジストリ）", syn="G-purpose")
R("rdap_dnt_allowed", "同意・目的・取引", "RDAP サーバー側での追跡・記録をしない（do not track）要求を許すかを示す。", K_RFC, "RFC 9560 §3.1.5.2", RFC(9560), "boolean", "ID",
  "RDAP の連携認証専用。" + VN, cc="IETF", syn="G-dnt")
R("vot", "認証の強さ・セッション", "Vector of Trust（身元確認・資格情報・管理・アサーションの各次元の値）。", K_RFC, "RFC 8485 §5", RFC(8485), "string", "ID",
  "ID トークンで使用。vtm（trustmark URL）とセットで送る MUST。広く実装されてはいない。" + VN, vocab="発行者ごと", syn="G-acr")
R("vtm", "認証の強さ・セッション", "vot の解釈基準となる trustmark の URL。", K_RFC, "RFC 8485 §5", RFC(8485), "string (URL)", "ID",
  "vot とセットで使用。" + VN, vocab="URI", syn="G-acr")

# =========================================================
# 15. SIP / PASSporT / STIR family
# =========================================================
PSP = "PASSporT（STIR、電話の発信者認証トークン）専用。一般の Web/API の ID・AT では使わない。"
for n, d, src, n_rfc, vt in [
    ("sip_from_tag", "SIP From ヘッダーの tag パラメータ値。", "RFC 8055", 8055, "string"),
    ("sip_date", "SIP Date ヘッダー値。", "RFC 8055", 8055, "string"),
    ("sip_callid", "SIP Call-Id ヘッダー値。", "RFC 8055", 8055, "string"),
    ("sip_cseq_num", "SIP CSeq の数値部分。", "RFC 8055", 8055, "string"),
    ("sip_via_branch", "SIP Via の branch パラメータ値。", "RFC 8055", 8055, "string")]:
    R(n, "監査・相関・イベント", d + "SIP 事業者間でルーティング用 realm 情報（Via ヘッダーの received-realm）を JWS で保護する際に使う。", K_RFC, src, RFC(n_rfc), vt, "その他（SIP Via received-realm の JWS）",
      "RFC 8055（2017-01）。SIP（電話網）専用で一般の ID/AT には現れない。typ=JWT。" + VN, syn="G-sip")
R("orig", "識別子", "発信者の識別情報（tn 電話番号または uri）。", K_RFC, "RFC 8225 §5.2.1", RFC(8225), "object", "その他（PASSporT）", PSP + "REQUIRED。" + VN, pii="直接識別できる個人情報", syn="G-passport-orig")
R("dest", "発行者・宛先", "着信先の識別情報（tn または uri の配列）。", K_RFC, "RFC 8225 §5.2.1", RFC(8225), "object", "その他（PASSporT）", PSP + "REQUIRED。" + VN, pii="直接識別できる個人情報", syn="G-passport-dest")
R("mky", "鍵・送信者制約", "メディア（DTLS-SRTP）鍵のフィンガープリント。", K_RFC, "RFC 8225 §5.2.2", RFC(8225), "array of object", "その他（PASSporT）", PSP + "OPTIONAL。" + VN, syn="G-passport-mky")
R("rph", "権限・認可", "SIP Resource-Priority ヘッダー（緊急・優先通話）の正当性を主張する。", K_RFC, "RFC 8443 §3", RFC(8443), "object", "その他（PASSporT rph 拡張）", PSP + VN, syn="G-sip-priority")
R("attest", "認証の強さ・セッション", "SHAKEN の発信者番号の証明レベル（A: 完全 / B: 部分 / C: ゲートウェイ）。", K_RFC, "RFC 8588 §4", RFC(8588), "string", "その他（PASSporT shaken 拡張）",
  PSP + "北米の SHAKEN フレームワーク。" + VN, vocab="標準で列挙（A, B, C）", syn="G-passport-attest")
R("origid", "監査・相関・イベント", "SHAKEN の発信元識別子（通話の発生源をトレースする UUID）。", K_RFC, "RFC 8588 §5", RFC(8588), "string (UUID)", "その他（PASSporT shaken 拡張）", PSP + VN, syn="G-passport-origid")
R("jcard", "プロフィール・連絡先", "着信拒否（SIP 608 応答）を行った仲介者の連絡先（jCard、RFC 7095）。", K_RFC, "RFC 8688 §3.2.2", RFC(8688), "array (jCard)", "その他（SIP 608 Call-Info の JWT）",
  "SIP 608 Rejected 応答専用。" + VN, pii="不明", syn="G-jcard")
R("div", "発行者・宛先", "転送（divert）された通話の転送先を示す。", K_RFC, "RFC 8946 §3", RFC(8946), "object", "その他（PASSporT div）", PSP + VN, syn="G-passport-div")
R("opt", "開示・暗号・検証補助", "転送前の元の PASSporT（フルフォーム）を内包する。", K_RFC, "RFC 8946 §6", RFC(8946), "string (PASSporT compact)", "その他（PASSporT div）", PSP + VN, syn="G-passport-div")
R("sph", "権限・認可", "SIP Priority ヘッダー（緊急サービスの psap-callback）の値を保護する。", K_RFC, "RFC 9027", RFC(9027), "string", "その他（PASSporT rph 拡張）", PSP + "緊急通報網向け。" + VN, syn="G-sip-priority")
R("atc", "権限・認可", "ACME の Authority Token Challenge（tkauth-type atc）で使う、識別子の権限を示すトークン情報。", K_RFC, "RFC 9447", RFC(9447), "object", "その他（ACME Authority Token）",
  "ACME（証明書発行）で電話番号等の識別子の権限を示す用途。" + VN, cc="IETF", syn="G-acme")
R("msgi", "開示・暗号・検証補助", "メッセージ（MIME ボディ）のダイジェスト。STIR をメッセージングに拡張する。", K_RFC, "RFC 9475", RFC(9475), "string", "その他（PASSporT）", PSP + VN, cc="IETF", syn="G-passport-msgi")
R("rcd", "プロフィール・連絡先", "Rich Call Data（発信者名 nam、アイコン icn、jCard jcd 等）。", K_RFC, "RFC 9795", RFC(9795), "object", "その他（PASSporT rcd 拡張）", PSP + "2025-07 RFC。" + VN, cc="IETF", pii="直接識別できる個人情報", syn="G-passport-rcd")
R("rcdi", "開示・暗号・検証補助", "rcd の各要素（外部参照を含む）の完全性ダイジェスト。", K_RFC, "RFC 9795 §6", RFC(9795), "object", "その他（PASSporT rcd 拡張）", PSP + VN, cc="IETF", syn="G-passport-rcd")
R("crn", "同意・目的・取引", "通話の理由（Call Reason）文字列。", K_RFC, "RFC 9795 §7", RFC(9795), "string", "その他（PASSporT rcd 拡張）", PSP + VN, cc="IETF", vocab="自由な文字列", syn="G-passport-rcd")
R("stpl", "開示・暗号・検証補助", "STIR 証明書の OCSP ステープル（失効確認結果）を PASSporT に同梱する。", K_DRAFT, "draft-ietf-stir-certificates-ocsp-14", STPL, "string", "その他（PASSporT）",
  PSP + "IANA には RFC-ietf-stir-certificates-ocsp-14 として登録済み（RFC 番号未付与、草案 -14 2026-06-10）。" + VN, status="草案（-14、RFC 編集待ち）", cc="IETF", fresh="発行時点で固定（寿命内は古いまま）", syn="G-ocsp")

# =========================================================
# 16. RFC 9711 EAT
# =========================================================
EAT = "Entity Attestation Token（デバイス・ソフトウェアのリモートアテステーション）専用。一般の ID/AT では使わない。JWT/CWT 両用。"
for n, d, vt, sec in [
    ("eat_nonce", "検証者が与えた鮮度確保用 nonce。", "string または array of string", "4.1"),
    ("ueid", "エンティティ（デバイス）の汎用一意 ID。", "string (base64url)", "4.2.1"),
    ("sueids", "工場リセット等で変わる半永続 UEID の集合。", "object", "4.2.2"),
    ("oemid", "ハードウェア製造者（OEM）の ID（乱数 / IEEE OUI / IANA PEN）。", "string または number", "4.2.3"),
    ("hwmodel", "ハードウェアのモデル識別子。", "string (base64url)", "4.2.4"),
    ("hwversion", "ハードウェアのバージョン。", "array", "4.2.5"),
    ("swname", "動作中ソフトウェアの名前。", "string", "4.2.6"),
    ("swversion", "動作中ソフトウェアのバージョン。", "array", "4.2.7"),
    ("oemboot", "起動したソフトウェアが OEM に認可されたものか。", "boolean", "4.2.8"),
    ("dbgstat", "デバッグ機能の状態（enabled / disabled / disabled-since-boot / disabled-permanently / disabled-fully-and-permanently）。", "number", "4.2.9"),
    ("location", "エンティティの地理的位置（緯度・経度等）。", "object", "4.2.10"),
    ("uptime", "起動からの秒数。", "number", "4.2.11"),
    ("bootcount", "起動回数。", "number", "4.2.12"),
    ("bootseed", "起動サイクルを識別する値。", "string (base64url)", "4.2.13"),
    ("dloas", "取得した認証（Digital Letters of Approval）。", "array", "4.2.14"),
    ("manifests", "インストール済みソフトウェアのマニフェスト。", "array", "4.2.15"),
    ("measurements", "ソフトウェア・構成の測定値。", "array", "4.2.16"),
    ("measres", "測定値と参照値の比較結果。", "array", "4.2.17"),
    ("submods", "サブモジュールの Claims-Set や入れ子トークン。", "object", "4.2.18"),
    ("eat_profile", "従っている EAT プロファイル。", "string (URI または OID)", "4.3.2"),
    ("intuse", "EAT の意図された用途（1 generic / 2 registration / 3 provisioning / 4 csr / 5 pop）。", "number", "4.3.3")]:
    R(n, "端末・ネットワーク・場所", d, K_RFC, "RFC 9711 §" + sec, RFC(9711), vt, "その他（EAT）", EAT + "2025-04 RFC。IANA 変更管理者 IETF。" + VN,
      cc="IETF", pii="機微な個人情報" if n == "location" else ("仮名の識別子" if n in ("ueid", "sueids") else "非該当"),
      fresh="発行ごとに再計算" if n in ("eat_nonce", "uptime", "location", "measurements", "measres", "dbgstat") else "発行時点で固定（寿命内は古いまま）",
      vocab="標準で列挙（RFC 9711）" if n in ("dbgstat", "intuse") else ("該当なし" if vt in ("number", "boolean") else "不明"),
      uniq="全体で一意" if n == "ueid" else "該当なし", syn="G-eat")
R("cmw", "端末・ネットワーク・場所", "RATS の概念メッセージ（エビデンス、アテステーション結果等）を包む Conceptual Message Wrapper。", K_RFC, "RFC 9999 §3.1, §3.3", RFC(9999), "array または object", "その他（RATS／EAT）",
  "リモートアテステーション（RATS）専用。2026-07 RFC。" + VN, cc="IETF", syn="G-eat")

# =========================================================
# 17. RFC 9246 CDNI URI signing
# =========================================================
CDN = "CDN 相互接続（CDNI）の URI 署名トークン専用。一般の ID/AT では使わない。"
for n, d, vt, sec in [("cdniv", "CDNI クレームセットのバージョン。", "number", "2.1.8"),
                      ("cdnicrit", "理解必須の CDNI クレーム名の一覧。", "array of string", "2.1.9"),
                      ("cdniip", "要求元クライアントの IP アドレス（トークンをその IP に限定）。", "string", "2.1.10"),
                      ("cdniuc", "署名対象 URI のパターン（URI Container: hash: / regex: 等）。", "string", "2.1.11"),
                      ("cdniets", "署名トークン更新時の有効期限設定（秒）。", "number", "2.1.12"),
                      ("cdnistt", "更新トークンの送り方（cookie / query 等）。", "number", "2.1.13"),
                      ("cdnistd", "パス式トークン伝送での深さ。", "number", "2.1.14")]:
    R(n, "端末・ネットワーク・場所" if n == "cdniip" else "権限・認可" if n == "cdniuc" else "トークン種別・メタ", d, K_RFC, "RFC 9246 §" + sec, RFC(9246), vt, "その他（CDNI URI 署名 JWT）",
      CDN + "2022-06 RFC。" + VN, cc="IETF", pii="不明" if n == "cdniip" else "非該当", syn="G-cdni")

# =========================================================
# 18. OpenID Federation 1.0
# =========================================================
FN = "OpenID Federation 1.0（2026-02-17 Final）のエンティティステートメント／トラストマーク等専用。通常の ID/AT では使わない。"
for n, d, vt, sec in [
    ("jwks", "暗号鍵の集合（JWK Set）。エンティティの連合用署名鍵など。", "object (JWK Set)", "13.1"),
    ("metadata", "JWT に関するメタデータ（エンティティ種別ごとのメタデータ）。", "object", "13.2"),
    ("constraints", "トラストチェーンに対する制約（max_path_length, naming_constraints 等）。", "object", "13.3"),
    ("crit", "理解・処理必須の拡張クレーム名の一覧。", "array of string", "13.4"),
    ("ref", "JWT に関するリソースの URI。", "string (URI)", "13.5"),
    ("delegation", "権限が委譲される相手を示す（大小区別の文字列）。", "string", "13.6"),
    ("logo_uri", "JWT に関するロゴの URI。", "string (URI)", "13.7"),
    ("authority_hints", "上位エンティティ（中間・トラストアンカー）の Entity ID の配列。", "array of string", "3.2"),
    ("trust_anchor_hints", "信頼するトラストアンカーのヒント。", "array of string", "3.2"),
    ("trust_marks", "保持するトラストマークの配列。", "array of object", "3.2"),
    ("trust_mark_issuers", "トラストマーク種別ごとの発行可能者。", "object", "3.2"),
    ("trust_mark_owners", "トラストマーク種別ごとの所有者。", "object", "3.2"),
    ("metadata_policy", "下位エンティティのメタデータに適用するポリシー。", "object", "3.3"),
    ("metadata_policy_crit", "理解必須のメタデータポリシー演算子。", "array of string", "3.3"),
    ("source_endpoint", "ステートメントを取得したエンドポイント URL。", "string (URL)", "3.3"),
    ("keys", "JWK Set 内の JWK の配列。", "array of object (JWK)", "5.2.1"),
    ("trust_mark_type", "トラストマーク種別の識別子。", "string", "7.1"),
    ("trust_chain", "トラストチェーン（JWT の配列）。", "array of string", "8.3.2"),
    ("trust_anchor", "トラストアンカーの Entity ID。", "string", "12.2.3")]:
    R(n, "鍵・送信者制約" if n in ("jwks", "keys") else ("発行者・宛先" if n in ("authority_hints", "trust_anchor_hints", "trust_anchor") else "トークン種別・メタ"),
      d, K_OIDF, "OpenID Federation 1.0 §" + sec, FED, vt, "その他（Federation エンティティステートメント等）", FN,
      vocab="URI" if n in ("ref", "logo_uri", "source_endpoint", "trust_anchor") else "不明", syn="G-federation")

# =========================================================
# 19. Others registered by non-IETF bodies (not opened)
# =========================================================
IANA_NOTE = "一次文書は未取得のため IANA 登録記載（名称・説明・参照）のみに基づく。"
R("at_use_nbr", "時刻・寿命", "アクセストークンを使える API 要求の回数。", K_OTHER, "IANA JWT Claims registry（ETSI GS NFV-SEC 022 V2.7.1）", IANA, "number", "AT",
  "ETSI NFV（ネットワーク機能仮想化）専用。" + IANA_NOTE, verified=False, status="不明", cc="ETSI", fresh="該当なし", syn="G-usage-count")
R("vc", "トークン種別・メタ", "W3C Verifiable Credential（VC Data Model 1.0 §6.3.1 の JWT 表現）。", K_OTHER, "IANA JWT Claims registry（W3C VC Data Model 1.0 §6.3.1）", IANA, "object", "証明書・VC",
  "VCDM 1.0（2019）の JWT エンコード。VCDM 2.0 では JOSE/COSE で別の表現（vc クレームを使わない）が定義されている点に注意。" + IANA_NOTE, verified=False, status="不明", cc="IESG", syn="G-vc")
R("vp", "トークン種別・メタ", "W3C Verifiable Presentation（VC Data Model 1.0 §6.3.1 の JWT 表現）。", K_OTHER, "IANA JWT Claims registry（W3C VC Data Model 1.0 §6.3.1）", IANA, "object", "証明書・VC",
  "VCDM 1.0 の JWT エンコード。" + IANA_NOTE, verified=False, status="不明", cc="IESG", syn="G-vc")
R("geohash", "端末・ネットワーク・場所", "Geohash 文字列（または配列）による地理的位置。", K_OTHER, "IANA JWT Claims registry（CTA-5009 Fast and Readable Geographical Hashing）", IANA, "string または array of string", "その他（CTA 仕様、用途は未確認）",
  "Consumer Technology Association 登録。" + IANA_NOTE, verified=False, status="不明", cc="Consumer Technology Association", pii="機微な個人情報", syn="G-location")
G3 = "3GPP 5G コア（NF 間の OAuth AT）専用。" + IANA_NOTE
for n, d in [("consumerPlmnId", "NF サービス利用者の PLMN ID。"), ("consumerSnpnId", "NF サービス利用者の SNPN ID。"),
             ("producerPlmnId", "NF サービス提供者の PLMN ID。"), ("producerSnpnId", "NF サービス提供者の SNPN ID。"),
             ("producerSnssaiList", "利用者に認可された提供者の S-NSSAI 一覧。"), ("producerNsiList", "利用者に認可された提供者の NSI 一覧。"),
             ("producerNfSetId", "提供者の NF Set ID。"), ("producerNfServiceSetId", "提供者の NF Service Set ID。"),
             ("sourceNfInstanceId", "送信元 NF の NF Instance ID。"), ("analyticsIdList", "Analytics ID の一覧。")]:
    R(n, "クライアント・ワークロード" if "Id" in n and "List" not in n else "権限・認可", d, K_OTHER, "IANA JWT Claims registry（3GPP TS 29.510 Clause 6.3.5.2.4）", IANA,
      "array" if "List" in n else "不明", "AT", G3, verified=False, status="不明", cc="3GPP", syn="G-3gpp")
R("resOwnerId", "識別子", "リソース所有者の識別子（例 3GPP TS 29.571 §5.3.2 の GPSI）。", K_OTHER, "IANA JWT Claims registry（3GPP TS 29.222 Clause 8.5.4.2.8）", IANA, "不明", "AT",
  "3GPP CAPIF（API 公開）専用。" + IANA_NOTE, verified=False, status="不明", cc="3GPP", pii="直接識別できる個人情報", syn="G-3gpp")

json.dump(ROWS, open(sys.argv[1], "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print(len(ROWS))

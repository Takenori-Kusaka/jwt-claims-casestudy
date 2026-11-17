# -*- coding: utf-8 -*-
import json, sys

D = "2026-11-17"
U = {
 "E_ID": "https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference",
 "E_AT": "https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference",
 "E_OPT": "https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference",
 "E_OPTCFG": "https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims",
 "E_AG": "https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/agent-token-claims",
 "E_EXT": "https://learn.microsoft.com/en-us/entra/identity-platform/schema-extensions",
 "E_MAP": "https://learn.microsoft.com/en-us/entra/identity-platform/reference-claims-customization",
 "E_JWTC": "https://learn.microsoft.com/en-us/entra/identity-platform/jwt-claims-customization",
 "E_SAML": "https://learn.microsoft.com/en-us/entra/identity-platform/reference-saml-tokens",
 "KC_A": "https://www.keycloak.org/docs/latest/server_admin/index.html",
 "KC_U": "https://www.keycloak.org/docs/latest/upgrading/index.html",
 "KC_T": "https://www.keycloak.org/securing-apps/token-exchange",
 "A0_C": "https://auth0.com/docs/secure/tokens/json-web-tokens/create-custom-claims",
 "A0_P": "https://auth0.com/docs/secure/tokens/access-tokens/access-token-profiles",
 "A0_O": "https://auth0.com/docs/secure/call-apis-on-users-behalf/on-behalf-of-token-exchange",
 "A0_G": "https://auth0.com/docs/ai-agents-mcp/agent-as-principal/agent-identity-in-tokens",
 "A0_ORG": "https://auth0.com/docs/manage-users/organizations/using-tokens",
 "A0_RBAC": "https://auth0.com/docs/get-started/apis/enable-role-based-access-control-for-apis",
 "A0_ID": "https://auth0.com/docs/manage-users/user-accounts/identify-users",
 "A0_IDT": "https://auth0.com/docs/secure/tokens/id-tokens/id-token-structure",
 "OK_R": "https://developer.okta.com/docs/reference/api/oidc/",
 "OK_G": "https://developer.okta.com/docs/guides/customize-tokens-groups-claim/main/",
 "OK_C": "https://developer.okta.com/docs/guides/customize-tokens-returned-from-okta/main/",
 "OK_T": "https://developer.okta.com/docs/guides/set-up-token-exchange/main/",
 "CG_ID": "https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-id-token.html",
 "CG_AT": "https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-access-token.html",
 "CG_PTG": "https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-token-generation.html",
 "CG_TE": "https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-token-exchange.html",
 "CG_STEP": "https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-step-up-authentication.html",
 "CG_ATTR": "https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html",
}
SRC = {
 "E_ID": "Microsoft Entra ID: ID token claims reference",
 "E_AT": "Microsoft Entra ID: Access token claims reference",
 "E_OPT": "Microsoft Entra ID: Optional claims reference",
 "E_OPTCFG": "Microsoft Entra ID: Configure optional claims",
 "E_AG": "Microsoft Entra Agent ID: Token claims reference for agents",
 "E_EXT": "Microsoft Entra ID: Directory extension attributes in claims",
 "E_MAP": "Microsoft Entra ID: Claims customization reference (restricted claim set)",
 "E_JWTC": "Microsoft Entra ID: Customize claims issued in the JWT",
 "E_SAML": "Microsoft Entra ID: SAML token claims reference",
 "KC_A": "Keycloak 26.x Server Administration Guide",
 "KC_U": "Keycloak Upgrading Guide (latest)",
 "KC_T": "Keycloak: Configuring and using token exchange",
 "A0_C": "Auth0 Docs: Create Custom Claims",
 "A0_P": "Auth0 Docs: Access Token Profiles",
 "A0_O": "Auth0 Docs: On-Behalf-Of Token Exchange",
 "A0_G": "Auth0 Docs: Agent identity in tokens (Agent as Principal)",
 "A0_ORG": "Auth0 Docs: Work with Tokens and Organizations",
 "A0_RBAC": "Auth0 Docs: Enable RBAC for APIs",
 "A0_ID": "Auth0 Docs: Identify Users",
 "A0_IDT": "Auth0 Docs: ID Token Structure",
 "OK_R": "Okta OpenID Connect & OAuth 2.0 API reference (Tokens and claims)",
 "OK_G": "Okta guide: Customize tokens with a groups claim",
 "OK_C": "Okta guide: Customize tokens returned from Okta",
 "OK_T": "Okta guide: Set up OAuth 2.0 On-Behalf-Of Token Exchange",
 "CG_ID": "Amazon Cognito Developer Guide: Understanding the ID token",
 "CG_AT": "Amazon Cognito Developer Guide: Understanding the access token",
 "CG_PTG": "Amazon Cognito Developer Guide: Pre token generation Lambda trigger",
 "CG_TE": "Amazon Cognito Developer Guide: Token exchange",
 "CG_STEP": "Amazon Cognito Developer Guide: Authentication levels with ACR and AMR claims",
 "CG_ATTR": "Amazon Cognito Developer Guide: User pool attributes",
}
VENDOR = {"E": "Entra", "K": "Keycloak", "A": "Auth0", "O": "Okta", "C": "Cognito"}
CC = {"E": "Microsoft", "K": "Keycloak プロジェクト（CNCF）", "A": "Okta（Auth0）", "O": "Okta", "C": "Amazon Web Services"}

rows = []

def R(v, name, cat, purpose, src, vt, token, notes, sup=None, extra_src=None, **kw):
    support = {k: "不明" for k in ["Entra", "Keycloak", "Auth0", "Okta", "Cognito"]}
    support[VENDOR[v]] = kw.pop("own", "既定")
    if sup:
        support.update(sup)
    multiplicity = "配列" if vt.startswith("array") else ("単一" if not vt.startswith("string or array") else "単一または配列（揺れあり）")
    row = {
        "name": name, "category": cat, "purpose": purpose,
        "source_kind": kw.pop("source_kind", "ベンダー独自"),
        "source": SRC[src] + (("; " + extra_src) if extra_src else ""),
        "url": U[src], "value_type": vt, "token": token, "support": support,
        "is_custom": kw.pop("is_custom", "独自（どの標準にもない）"),
        "notes": notes, "verified": kw.pop("verified", True),
        "status": kw.pop("status", "ベンダー提供中"),
        "change_controller": CC[v],
        "writer": kw.pop("writer", "不明"),
        "mutability": kw.pop("mut", "不明"),
        "freshness": kw.pop("fresh", "発行時点で固定（寿命内は古いまま）"),
        "authz_use": kw.pop("authz", "記載なし"),
        "pii": kw.pop("pii", "非該当"),
        "log_policy": kw.pop("log", "記載なし"),
        "multiplicity": kw.pop("mult", multiplicity),
        "limit": kw.pop("limit", "記載なし"),
        "comparison": kw.pop("cmp", "記載なし"),
        "uniqueness": kw.pop("uniq", "記載なし"),
        "vocabulary": kw.pop("vocab", "記載なし"),
        "synonym_group": kw.pop("syn", ""),
        "checked_on": D,
    }
    assert not kw, (name, kw)
    rows.append(row)

STD = "標準だが値の語彙は独自"
STDK = "標準"
ISS = "発行者（権威ある情報源）"
DER = "発行者が派生"
CLI = "呼び出し元・クライアントの申告"
DIR = "発行者（取得元から転記）"

# ============================ Microsoft Entra ID ============================
E = "E"
R(E, "aio", "トークン種別・メタ", "トークン再利用のためのデータを記録する Entra 内部の不透明クレーム。アプリ・リソースは使ってはならず、意味のある属性ではない。", "E_AT", "string（不透明）", "両方",
  "ID トークン・アクセストークン両方の既定クレーム。「Should be ignored」と明記。claims mapping の restricted claim set にも含まれ変更不可。", extra_src="ID token claims reference", writer=ISS, authz="不可（表示・監査用）", syn="G-internal")
R(E, "rh", "トークン種別・メタ", "トークン再検証に使う Entra 内部の不透明クレーム。アプリは無視すべきで、セッションや利用者を表さない。", "E_AT", "string（不透明）", "両方",
  "「Resources shouldn't use this claim」。restricted claim set。", extra_src="ID token claims reference", writer=ISS, authz="不可（表示・監査用）", syn="G-internal")
R(E, "uti", "トークン種別・メタ", "トークン識別子。JWT の jti 相当の一意・大小区別のトークン ID。利用者やセッションの ID ではない。", "E_AT", "string", "両方",
  "Entra は jti ではなく uti を出す（jti 前提のリプレイ検知ライブラリは要調整）。", writer=ISS, mut="不変", cmp="大小区別の完全一致", uniq="全体で一意", syn="G-token-id", sup={"Keycloak": "独自の名前で", "Auth0": "独自の名前で", "Okta": "独自の名前で", "Cognito": "独自の名前で"},
  extra_src="ID token claims reference")
R(E, "ver", "トークン種別・メタ", "トークン形式のバージョン（\"1.0\" または \"2.0\"）。v1/v2 で iss・aud・クレーム集合が異なることを示す。API の権限やユーザー属性ではない。", "E_AT", "string（\"1.0\" | \"2.0\"）", "両方",
  "AT のバージョンは API 側マニフェストの requestedAccessTokenVersion で決まり、クライアントが呼ぶエンドポイントではない（ID トークンはエンドポイントで決まる）。Okta の ver は integer で意味も別。", writer=ISS, vocab="標準で列挙（1.0 / 2.0、Entra 文書）", syn="G-token-version", sup={"Okta": "独自の名前で"})
R(E, "idtyp", "トークン種別・メタ", "トークンの主体種別。既定では app-only トークンにのみ \"app\" が入り、API がアプリトークンかユーザー＋アプリかを判定する最も正確な手段。Agent ID では user/app。", "E_OPT", "string（app | user | device）", "AT",
  "optional claim。ユーザートークンにも出すには additionalProperties の include_user_token が必要（リソース側で設定）。groups overage 時に Microsoft Graph URL を組み立てる判定にも使うよう案内。Agent ID: idtyp 単独では人間とエージェントのユーザーアカウントを区別できず xms_sub_fct=13 を見る。",
  extra_src="Access token claims reference; Agent ID token claims", own="設定で追加", writer=DER, authz="補助のみ", vocab="標準で列挙（app/user/device、Entra 文書）", syn="G-subject-type", sup={"Auth0": "独自の名前で"})
R(E, "oid", "識別子", "ユーザーまたはサービスプリンシパルの不変 GUID。同一テナント内でアプリ間共通、Microsoft Graph の id と同じ。テナントが違えば同じ人でも別値。", "E_ID", "string（GUID）", "両方",
  "受け取るには profile スコープが必要（ユーザーの場合）。サービス間で共有するキーは oid+tid が推奨。再利用されない。Agent ID ではシナリオによりユーザー / エージェント identity / エージェントのユーザーアカウントの OID。SAML: http://schemas.microsoft.com/identity/claims/objectidentifier。",
  extra_src="Access token claims reference; SAML token claims reference", writer=ISS, mut="不変", authz="iss・aud などと組で可", pii="仮名の識別子", cmp="大小区別なし", uniq="発行者内で一意", syn="G-user-id")
R(E, "tid", "組織・テナント", "利用者がサインインしたテナントの不変 GUID。個人 MSA テナントは 9188040d-6c67-4c5b-b112-36a304b66dad。ユーザー ID ではない。", "E_ID", "string（GUID）", "両方",
  "AT で受けるには profile スコープが必要と記載。マルチテナントでは iss の {tenantid} を tid で置換して照合、データキーにも含める。SAML: http://schemas.microsoft.com/identity/claims/tenantid（restricted）。Agent ID: エージェント identity が登録された顧客テナント。",
  extra_src="Access token claims reference", writer=ISS, mut="不変", authz="iss・aud などと組で可", pii="非該当", uniq="全体で一意", syn="G-tenant", sup={"Auth0": "独自の名前で", "Keycloak": "独自の名前で"})
R(E, "sub", "識別子", "トークンの主体。Entra では不変・再利用されないペアワイズ ID で、アプリケーション ID（client ID）ごとに値が異なる。同じ人でもアプリが違えば一致しない。", "E_ID", "string", "両方",
  "OIDC 標準の sub だが Entra 固有の制約: 受信者・テナント・ユーザーの組合せから算出。アプリ間で共有するキーには oid を使う。AT 文書は認可チェックや DB キーに使えると記載。", is_custom=STD,
  extra_src="Access token claims reference", writer=DER, mut="不変", authz="iss・aud などと組で可", pii="仮名の識別子", uniq="発行者内で一意", syn="G-user-id")
R(E, "iss", "発行者・宛先", "トークンを発行した STS とユーザーのテナントを示す URI。v2.0 トークンでは末尾が /v2.0、v1.0 は sts.windows.net 形式（例示）。", "E_AT", "string（URI）", "両方",
  "標準 iss だが Entra 固有: v1/v2 で形式が異なり、common/organizations メタデータの issuer は {tenantid} テンプレート。GUID 部分でテナントを制限できる。SAML の Issuer 要素に対応。", is_custom=STD,
  extra_src="ID token claims reference; SAML token claims reference", writer=ISS, mut="不変", authz="iss・aud などと組で可", cmp="大小区別の完全一致", vocab="URI", syn="G-issuer")
R(E, "aud", "発行者・宛先", "トークンの受信者。ID トークンはアプリの Application ID、v2 AT は常に API の client ID、v1 AT は client ID またはリクエストで使ったリソース URI（App ID URI）。", "E_AT", "string（GUID または App ID URI）", "両方",
  "v1 AT では末尾スラッシュ有無など揺れるため、リソース側 optional claim aud の additionalProperties use_guid で client ID に固定できる。複数値（配列）ではなく単一文字列。", is_custom=STD,
  extra_src="ID token claims reference; Optional claims reference (use_guid)", writer=DER, authz="iss・aud などと組で可", cmp="正規化が必要", syn="G-audience")
R(E, "iat", "時刻・寿命", "Entra 文書では「このトークンの認証が行われた時刻」と説明される Unix 時刻。", "E_AT", "number（NumericDate）", "両方",
  "RFC 7519 の iat（発行時刻）と説明文言が異なる（authentication occurred と記載）点に注意。厳密な認証時刻は optional claim auth_time。", is_custom=STD, extra_src="ID token claims reference", writer=ISS, mut="不変", fresh="該当なし", syn="G-iat")
R(E, "exp", "時刻・寿命", "これ以降トークンを受理してはならない時刻。Entra では認証変更や失効検知によりリソースが期限前に拒否し得る。", "E_AT", "number（NumericDate）", "両方",
  "AT 既定寿命 60–90 分のランダム（平均 75 分、研究ノート）。CAE セッションでは最大 28 時間（研究ノート、CAE 文書）。", is_custom=STD, extra_src="ID token claims reference", writer=ISS, fresh="該当なし", syn="G-exp")
R(E, "idp", "認証の強さ・セッション", "主体を認証した IdP（通常 STS URI）。ゲストなど発行テナント外のアカウントで iss と異なる。無ければ iss を使う。個人アカウントでは live.com 等。", "E_AT", "string（通常 STS URI）", "両方",
  "テナント横断の利用者名寄せに idp を使ってはならない（oid/sub はテナントごとに変わる設計）。SAML: http://schemas.microsoft.com/identity/claims/identityprovider。", extra_src="ID token claims reference; SAML token claims reference", writer=ISS, authz="補助のみ", vocab="URI", syn="G-idp", sup={"Okta": "既定（ID のみ）", "Cognito": "独自の名前で"}, is_custom="独自（どの標準にもない）")
R(E, "nbf", "時刻・寿命", "これより前は JWT を処理してはならない時刻。標準 nbf と同義（Entra は既定で付与）。", "E_AT", "number（NumericDate）", "両方",
  "標準 RFC 7519 nbf と意味の差はない。既定で付与される事実の記録のみ（標準行は別エージェント）。", is_custom=STDK, extra_src="ID token claims reference", writer=ISS, fresh="該当なし", syn="G-nbf")
R(E, "c_hash", "開示・暗号・検証補助", "認可コードのハッシュ。ID トークンが認可コードと共に発行されたときのみ含まれる。", "E_ID", "string", "ID",
  "Entra 固有の制約: /token エンドポイントから返る ID トークンには含まれない。", is_custom=STD, writer=DER, syn="G-c_hash")
R(E, "at_hash", "開示・暗号・検証補助", "アクセストークンのハッシュ。/authorize エンドポイントから AT と共に発行された ID トークンにのみ含まれる。", "E_ID", "string", "ID",
  "Entra 固有の制約: /token エンドポイントから返る ID トークンには含まれない。restricted claim set。", is_custom=STD, writer=DER, syn="G-at_hash")
R(E, "preferred_username", "プロフィール・連絡先", "利用者を表す主たるユーザー名（メール・電話番号・形式なし文字列のいずれか）。可変で認可判断に使えず、ヒントや表示用。", "E_ID", "string", "両方",
  "v2.0 トークンのみ（v1 は optional claim preferred_username で追加可）。profile スコープが必要。", is_custom=STD, extra_src="Access token claims reference; Optional claims reference", writer=DIR, mut="改名・変更あり", authz="不可（表示・監査用）", pii="直接識別できる個人情報", syn="G-username")
R(E, "email", "プロフィール・連絡先", "報告されたメールアドレス。ゲストには既定、テナント内ユーザーは optional claim または v2 の email スコープで要求。正しさは保証されず可変。", "E_ID", "string", "両方",
  "「Never use it for authorization or to save data for a user」。正しさ保証なし。ドメイン検証状態は xms_edov、権威ある値は verified_primary_email。", is_custom=STD, extra_src="Optional claims reference", own="設定で追加", writer=DIR, mut="随時変わる", authz="不可（表示・監査用）", pii="直接識別できる個人情報", syn="G-email")
R(E, "name", "プロフィール・連絡先", "主体の人間可読名。一意でなく変更され得るため表示専用。", "E_ID", "string", "両方",
  "profile スコープが必要。", is_custom=STD, extra_src="Access token claims reference", writer=DIR, mut="改名・変更あり", authz="不可（表示・監査用）", pii="直接識別できる個人情報", syn="G-name")
R(E, "nonce", "開示・暗号・検証補助", "authorize 要求に含めた nonce の値。一致しなければアプリはトークンを拒否する。", "E_ID", "string", "ID",
  "標準と同義。Entra が ID トークンに付与する事実の記録。", is_custom=STDK, writer=CLI, cmp="大小区別の完全一致", syn="G-nonce")
R(E, "roles", "権限・認可", "AT: 呼び出し側（アプリ）に付与されたアプリケーション許可、またはユーザー トークンでは対象アプリでのユーザーのアプリロール。ID: サインインしたユーザーに割り当てられたロール。", "E_AT", "array of string", "両方",
  "client credentials では scp の代わりに roles。事前承認ロールを含み得る。groups の emit_as_roles を使うとグループ値が roles に入り、アプリロールは出なくなる。SAML: http://schemas.microsoft.com/ws/2008/06/identity/claims/role。網羅的な認可手段ではないと注記。", is_custom=STD,
  extra_src="ID token claims reference; Optional claims (emit_as_roles)", writer=ISS, authz="単独で可", vocab="発行者ごと", syn="G-roles", sup={"Keycloak": "独自の名前で", "Auth0": "フック・式で可", "Okta": "フック・式で可", "Cognito": "独自の名前で"})
R(E, "sid", "認証の強さ・セッション", "セッションの一意識別子（GUID）。新しいセッション確立時に生成される。", "E_ID", "string（GUID）", "両方",
  "標準 sid（OIDC Front/Back-Channel Logout）と同名。Entra では GUID 形式と明記。restricted claim set。", is_custom=STD, extra_src="Access token claims reference", writer=ISS, pii="仮名の識別子", syn="G-session")
R(E, "unique_name", "プロフィール・連絡先", "主体の人間可読名（v1.0 のみ）。テナント内で一意とは限らず表示専用。", "E_ID", "string", "両方",
  "v1.0 トークンのみ。認可・保存キーに使ってはならない（claims validation の警告、研究ノート）。SAML: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name。", extra_src="Access token claims reference; SAML token claims reference", writer=DIR, mut="改名・変更あり", authz="不可（表示・監査用）", pii="直接識別できる個人情報", syn="G-username")
R(E, "hasgroups", "権限・認可", "存在すれば常に true。ユーザーが少なくとも 1 つのグループに属し、グループは Microsoft Graph（getMemberObjects）で取得すべきことを示す。", "E_ID", "boolean（常に true）", "両方",
  "長さ制限のある要求（研究ノートでは implicit flow、未検証）で groups の代わりに出る。所属なしを意味しない。", extra_src="Access token claims reference", writer=DER, authz="補助のみ", syn="G-groups-overage")
R(E, "groups", "権限・認可", "主体のグループ所属を表すオブジェクト ID（GUID）の配列。groupMembershipClaims（SecurityGroup / DirectoryRole / All / ApplicationGroup）で出力。", "E_AT", "array of string（GUID 既定）", "両方",
  "JWT 200 件（SAML 150 件、ネスト含む）超で groups を出さず _claim_names/_claim_sources に置換。optional claim groups の additionalProperties（sam_account_name / dns_domain_and_sam_account_name / netbios_domain_and_sam_account_name / cloud_displayname / emit_as_roles）で値形式を変更可。グループ optional claim はユーザープリンシパルのみ。SAML: http://schemas.microsoft.com/ws/2008/06/identity/claims/groups。", is_custom=STD,
  extra_src="Optional claims (Configure groups optional claims)", own="設定で追加", writer=ISS, authz="単独で可", limit="JWT 200 件（SAML 150 件）超で欠落し _claim_names/_claim_sources に置換", vocab="発行者ごと", syn="G-groups",
  sup={"Keycloak": "設定で追加", "Auth0": "フック・式で可", "Okta": "設定で追加", "Cognito": "独自の名前で"})
R(E, "groups:src1", "権限・認可", "長さ制限はないがトークンに収まらない場合のグループ一覧へのリンク。JWT では分散クレーム、SAML では groups の代わりの新クレーム。", "E_ID", "object", "両方",
  "文書上の表記。JWT 例は \"groups\":\"src1\" と _claim_sources.src1.endpoint。SAML: http://schemas.microsoft.com/claims/groups.link（URL は graph.windows.net）。", extra_src="Access token claims reference; SAML token claims reference", writer=DER, authz="補助のみ", syn="G-groups-overage")
R(E, "_claim_names", "開示・暗号・検証補助", "groups overage 時に groups クレームが分散クレーム src1 にあることを示すオブジェクト（{\"groups\":\"src1\"}）。", "E_AT", "object", "両方",
  "OIDC Core の Aggregated/Distributed Claims 機構を利用。返る endpoint は Azure AD Graph（graph.windows.net）なので頼らず、idtyp を見て Microsoft Graph URL を組み立てる。restricted claim set。", is_custom=STD, extra_src="ID token claims reference", writer=DER, authz="補助のみ", syn="G-groups-overage")
R(E, "_claim_sources", "開示・暗号・検証補助", "分散クレームの取得元（src1.endpoint にグループ取得 URL）。", "E_AT", "object", "両方",
  "groups overage 時のみ。URL は graph.windows.net を返すと明記。restricted claim set。", is_custom=STD, extra_src="ID token claims reference", writer=DER, authz="補助のみ", syn="G-groups-overage")
R(E, "acrs", "認証の強さ・セッション", "持参者が実行資格を持つ操作の Auth Context ID の配列。アプリ内からステップアップ認証を要求する契機に使う。", "E_AT", "array of string", "AT",
  "xms_cc と併用されることが多い。optional claim（Entra ID ユーザー）。restricted claim set。", extra_src="Optional claims reference", own="設定で追加", writer=ISS, authz="iss・aud などと組で可", vocab="発行者ごと", syn="G-acr")
R(E, "acr", "認証の強さ・セッション", "v1.0 トークンのみの \"0\" または \"1\"。0 はエンドユーザー認証が ISO/IEC 29115 の要件を満たさないことを示す。", "E_AT", "string（\"0\" | \"1\"）", "AT",
  "OIDC 標準 acr と同名だが値は 0/1 のみで v1.0 限定。ステップアップ判定には acrs を使う。", is_custom=STD, writer=ISS, vocab="標準で列挙（0/1、Entra 文書）", syn="G-acr")
R(E, "amr", "認証の強さ・セッション", "主体の認証方法の配列（例 [\"mfa\",\"rsa\",\"pwd\"]）。Entra 独自の値語彙（pwd, rsa, otp, fed, wia, mfa, ngcmfa, wiaormfa, none, totp, hotp, swk, sms, tel, emailotp, fido, hwk, x509 など）。", "E_AT", "array of string", "両方",
  "v1.0 では既定、v2.0 は optional claim で要求。x509 単独はフィッシング耐性 MFA ではない。外部 MFA の amr を転送。SAML は include_granular_amr が必要（http://schemas.microsoft.com/claims/authnmethodsreferences）。", is_custom=STD,
  extra_src="Optional claims reference (AMR values)", writer=ISS, authz="補助のみ", vocab="発行者ごと", syn="G-amr")
R(E, "appid", "クライアント・ワークロード", "トークンを使うクライアントのアプリケーション ID（v1.0 のみ）。アプリ自身またはユーザー代理として動作。", "E_AT", "string（GUID）", "AT",
  "v2.0 では azp に置換。認可判断に使ってよいと明記。Agent ID ではエージェント identity のアプリ ID。", writer=ISS, authz="単独で可", uniq="発行者内で一意", syn="G-client-id", sup={"Keycloak": "独自の名前で", "Auth0": "独自の名前で", "Okta": "独自の名前で", "Cognito": "独自の名前で"})
R(E, "azp", "クライアント・ワークロード", "v2.0 AT で appid の代替となる、トークンを使うクライアントのアプリケーション ID。", "E_AT", "string（GUID）", "AT",
  "OIDC Core の azp（ID トークンの authorized party）と名前は同じだが、Entra では AT に常にクライアント ID を入れる用途。Agent ID ではエージェント identity。", is_custom=STD, writer=ISS, authz="単独で可", syn="G-client-id")
R(E, "appidacr", "クライアント・ワークロード", "クライアントの認証方式（v1.0 のみ）: 0=public client、1=client secret、2=クライアント証明書。", "E_AT", "string（\"0\"|\"1\"|\"2\"）", "AT",
  "v2.0 では azpacr。", writer=ISS, authz="補助のみ", vocab="標準で列挙（0/1/2、Entra 文書）", syn="G-client-auth")
R(E, "azpacr", "クライアント・ワークロード", "クライアントの認証方式（v2.0 のみ）: 0=public、1=secret、2=証明書。", "E_AT", "string（\"0\"|\"1\"|\"2\"）", "AT",
  "appidacr の代替。", writer=ISS, authz="補助のみ", vocab="標準で列挙（0/1/2、Entra 文書）", syn="G-client-auth")
R(E, "scp", "権限・認可", "アプリが公開し、クライアントが同意を得た（受け取った）スコープの空白区切りリスト。ユーザートークンのみ。", "E_AT", "string（space-delimited）", "AT",
  "事前承認スコープを含み得る。アプリトークンは roles。Agent ID 自律フローでは空または \"/\"。Okta の scp は配列で型が違う。", writer=ISS, authz="単独で可", vocab="発行者ごと", syn="G-scope", sup={"Okta": "独自の名前で", "Keycloak": "独自の名前で", "Auth0": "独自の名前で", "Cognito": "独自の名前で"})
R(E, "wids", "権限・認可", "ユーザーに割り当てられたテナント全体の Entra 組み込みロールの RoleTemplateID GUID 配列。", "E_AT", "array of string（GUID）", "AT",
  "groupMembershipClaims を All または DirectoryRole にすると出力。", own="設定で追加", writer=ISS, authz="単独で可", syn="G-roles")
R(E, "xms_cc", "クライアント・ワークロード", "トークンを取得したクライアントが claims challenge を処理できるか。cp1 が AT 内にあることが権威ある判定。", "E_AT", "array of string", "AT",
  "リソース（API）側が optional claim として要求しないと出ない。CA / CAE シナリオで acrs と併用。", extra_src="Optional claims reference", own="設定で追加", writer=CLI, vocab="発行者ごと", syn="G-client-capability")
R(E, "ipaddr", "端末・ネットワーク・場所", "利用者が認証した IP アドレス。", "E_AT", "string", "両方",
  "v1.0 では既定、v2.0 は optional claim。restricted claim set。", extra_src="Optional claims reference", own="既定（v1 のみ）", writer=ISS, pii="直接識別できる個人情報", syn="G-ip")
R(E, "onprem_sid", "識別子", "オンプレミス認証がある利用者の SID。レガシーアプリの認可用。", "E_AT", "string（SID 形式）", "両方",
  "v1.0 既定、v2.0 は optional claim。", extra_src="Optional claims reference", own="既定（v1 のみ）", writer=DIR, pii="仮名の識別子", syn="G-user-id")
R(E, "pwd_exp", "時刻・寿命", "パスワードの有効期限（AT 文書: Unix 時刻 / Optional 文書: iat からの秒数）。パスワード期限が近いときのみ。", "E_AT", "number", "両方",
  "2 文書で値の説明が食い違う（Unix timestamp と iat 起点の秒数）。v1 既定・v2 optional。", extra_src="Optional claims reference", own="既定（v1 のみ）", writer=DIR, syn="G-password")
R(E, "pwd_url", "その他", "パスワードを変更（リセット）できる URL。パスワード期限が近いときのみ。", "E_AT", "string（URL）", "両方",
  "v1 既定・v2 optional。", extra_src="Optional claims reference", own="既定（v1 のみ）", writer=ISS, syn="G-password")
R(E, "in_corp", "端末・ネットワーク・場所", "クライアントが企業ネットワークからサインインしているか。MFA の信頼できる IP 設定に基づく。社外の場合は出ない。", "E_AT", "boolean", "両方",
  "v1 既定・v2 optional。", extra_src="Optional claims reference", own="既定（v1 のみ）", writer=DER, authz="補助のみ", syn="G-network")
R(E, "nickname", "プロフィール・連絡先", "名・姓とは別の利用者の別名。", "E_AT", "string", "両方",
  "v1.0 basic claims として列挙。restricted claim set。", is_custom=STD, own="既定（v1 のみ）", writer=DIR, pii="直接識別できる個人情報", syn="G-name")
R(E, "family_name", "プロフィール・連絡先", "ユーザーオブジェクトの姓。", "E_OPT", "string", "両方",
  "v1 既定、v2 は optional claim（profile スコープ必要、MSA/Entra 両対応）。SAML: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname。", is_custom=STD, extra_src="Access token claims reference", own="既定（v1 のみ）", writer=DIR, mut="改名・変更あり", pii="直接識別できる個人情報", syn="G-name")
R(E, "given_name", "プロフィール・連絡先", "ユーザーオブジェクトの名。", "E_OPT", "string", "両方",
  "v1 既定、v2 は optional claim（profile スコープ必要）。SAML: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname。", is_custom=STD, extra_src="Access token claims reference", own="既定（v1 のみ）", writer=DIR, mut="改名・変更あり", pii="直接識別できる個人情報", syn="G-name")
R(E, "upn", "識別子", "ユーザー名（UPN）。電話番号・メール・形式なし文字列のいずれか。表示や再認証時のヒント用で、永続 ID ではない。", "E_OPT", "string", "両方",
  "認可・DB キーに使わない（oid を使う）。代替ログイン ID のユーザーには表示しない。additionalProperties include_externally_authenticated_upn(_without_hash) でゲスト UPN 形式を変更。v1 既定。", extra_src="Access token claims reference", writer=DIR, mut="改名・変更あり", authz="不可（表示・監査用）", pii="直接識別できる個人情報", syn="G-username", sup={"Keycloak": "設定で追加"})
R(E, "acct", "識別子", "テナント内のユーザーアカウント状態。メンバーは 0、ゲストは 1。", "E_OPT", "number（0 | 1）", "両方",
  "optional claim（JWT・SAML）。", own="設定で追加", writer=DER, authz="補助のみ", vocab="標準で列挙（0/1、Entra 文書）", syn="G-user-type")
R(E, "auth_time", "時刻・寿命", "利用者が最後に認証した時刻。", "E_OPT", "number（NumericDate）", "両方",
  "Entra では optional claim（既定では出ない）。", is_custom=STD, own="設定で追加", writer=ISS, fresh="該当なし", syn="G-auth_time")
R(E, "ctry", "端末・ネットワーク・場所", "利用者の国/地域（FR, JP などの 2 文字コード）。値が存在し標準 2 文字の場合のみ。", "E_OPT", "string（ISO 2 文字）", "両方",
  "optional claim。", own="設定で追加", writer=DIR, pii="直接識別できる個人情報", syn="G-country")
R(E, "fwd", "端末・ネットワーク・場所", "VNET 内から要求したクライアントの元の IP アドレス。", "E_OPT", "string", "両方",
  "optional claim。", own="設定で追加", writer=ISS, pii="直接識別できる個人情報", syn="G-ip")
R(E, "login_hint", "識別子", "base64 エンコードされた不透明で信頼できるログインヒント。SSO の login_hint パラメータに使う最適値。", "E_OPT", "string（不透明, base64）", "両方",
  "改変してはならない。現在テナントを含まず既定でホームテナント。UPN など人間可読値より信頼できる。", own="設定で追加", writer=DER, authz="不可（表示・監査用）", pii="仮名の識別子", syn="G-login-hint")
R(E, "tenant_ctry", "組織・テナント", "リソーステナントの国/地域（管理者がテナント単位で設定する 2 文字コード）。", "E_OPT", "string（ISO 2 文字）", "両方",
  "optional claim。コンシューマーアカウントには値なし。", own="設定で追加", writer=DIR, syn="G-country")
R(E, "tenant_region_scope", "組織・テナント", "リソーステナントのリージョン。", "E_OPT", "string", "両方",
  "optional claim。値の形式は文書に記載なし。", own="設定で追加", writer=DIR, syn="G-tenant")
R(E, "verified_primary_email", "プロフィール・連絡先", "ユーザーの PrimaryAuthoritativeEmail を元にした値。", "E_OPT", "string", "両方",
  "optional claim。詳細説明なし。restricted claim set。", own="設定で追加", writer=DIR, pii="直接識別できる個人情報", syn="G-email")
R(E, "verified_secondary_email", "プロフィール・連絡先", "ユーザーの SecondaryAuthoritativeEmail を元にした値。", "E_OPT", "string", "両方",
  "optional claim。詳細説明なし。", own="設定で追加", writer=DIR, pii="直接識別できる個人情報", syn="G-email")
R(E, "vnet", "端末・ネットワーク・場所", "VNET 指定子の情報。", "E_OPT", "string", "両方",
  "optional claim。形式は記載なし（value_type は推定せず string と記録したが文書に型記載なし）。", own="設定で追加", writer=ISS, syn="G-network")
R(E, "xms_edov", "本人確認・保証", "利用者のメールドメイン所有者が検証済みかを示す真偽値。", "E_OPT", "boolean", "両方",
  "テナントのドメインで管理者検証済み、または MSA/Google/OTP のメールなら検証済み。Facebook や SAML/WS-Fed は対象外。email クレームの存在が必要。", own="設定で追加", writer=DER, authz="補助のみ", syn="G-email-verified")
R(E, "xms_pdl", "端末・ネットワーク・場所", "Multi-Geo テナントでの優先データ所在地（3 文字の地域コード）。", "E_OPT", "string（3 文字）", "両方",
  "optional claim。", own="設定で追加", writer=DIR, syn="G-data-location")
R(E, "xms_pl", "プロフィール・連絡先", "利用者の優先言語（LL-CC 形式、例 en-us）。ゲストではホームテナント由来。", "E_OPT", "string", "両方",
  "optional claim。", own="設定で追加", writer=DIR, syn="G-locale", sup={"Keycloak": "独自の名前で", "Okta": "独自の名前で", "Auth0": "独自の名前で", "Cognito": "独自の名前で"})
R(E, "xms_tpl", "組織・テナント", "リソーステナントの優先言語（LL 形式、例 en）。", "E_OPT", "string", "両方",
  "optional claim。", own="設定で追加", writer=DIR, syn="G-locale")
R(E, "ztdid", "端末・ネットワーク・場所", "Windows AutoPilot に使うデバイス ID（Zero-touch Deployment ID）。", "E_OPT", "string", "両方",
  "optional claim。restricted claim set。", own="設定で追加", writer=DIR, pii="仮名の識別子", syn="G-device")
R(E, "extn.<attributename>", "その他", "ディレクトリ拡張属性（extension_<appid>_<name>）の値を JWT に出すときの名前形式。", "E_OPTCFG", "string（属性型による）", "両方",
  "マニフェストでは extension_<appid>_<attributename> で指定し、JWT では extn.<attributename>、SAML では http://schemas.microsoft.com/identity/claims/extn.<attributename>。MSA ユーザーには返らない。別アプリ登録の拡張は claims mapping policy（ExtensionID）で任意 JWTClaimType に写像。ユーザーオブジェクトの拡張のみ可。カスタムセキュリティ属性は JWT/SAML クレームに非対応（Custom security attributes overview）。restricted claim set に「extn. as prefix」。", extra_src="Directory extension attributes in claims", own="設定で追加", writer="本人が編集できる", pii="不明", syn="G-custom-attr")
R(E, "（claims mapping / custom claims policy で定義する任意クレーム）", "その他", "エンタープライズアプリのクレームカスタマイズ（Attributes & Claims）や claims mapping policy で定義する任意名の JWT クレーム。名前は URI 形式でなくてよく、名前空間フィールドも使える。", "E_JWTC", "string または array（ソース属性による）", "両方",
  "マルチテナントアプリはカスタム署名キー必須（acceptMappedClaims を設定しない）。シングルテナントは acceptMappedClaims=true 可。カスタム署名キー使用時は metadata に appid={client_id} を付けて jwks_uri を取得。restricted claim set（JWT 約 200 名、xms_ で始まる全クレーム）は名前に使えない。claims mapping policy は custom claims policy・ポータル設定より優先。", extra_src="Claims customization reference", own="設定で追加", writer="不明", syn="G-custom-attr", sup={"Keycloak": "設定で追加", "Auth0": "フック・式で可", "Okta": "設定で追加", "Cognito": "フック・式で可"})
R(E, "xms_act_fct", "委任・行為者", "トークンのアクター（azp / appid）に関する事実（facets）。空白区切りの奇数整数の多値で、11=AgentIdentity、13=AgentIDUser。", "E_AG", "string（space-delimited integers）", "AT",
  "Entra Agent ID。値の順序を仮定しない・関係ない値は無視。OBO・自律・エージェントユーザーアカウントの全シナリオで 11。ページ最終更新 2026-11-06。プレビュー/GA 表記は確認できず。", writer=DER, authz="補助のみ", vocab="標準で列挙（Entra Agent ID 文書）", syn="G-actor", sup={"Auth0": "独自の名前で", "Keycloak": "独自の名前で", "Okta": "独自の名前で", "Cognito": "独自の名前で"})
R(E, "xms_sub_fct", "委任・行為者", "トークンの主体（sub）に関する事実。11=AgentIdentity、13=AgentIDUser（エージェントのユーザーアカウント）。", "E_AG", "string（space-delimited integers）", "AT",
  "idtyp=user だけでは人間とエージェントのユーザーアカウントを区別できず、13 で判別する。", writer=DER, authz="補助のみ", vocab="標準で列挙（Entra Agent ID 文書）", syn="G-subject-type", sup={"Auth0": "独自の名前で"})
R(E, "xms_tnt_fct", "組織・テナント", "tid が示すテナントに関する事実（多値・奇数整数）。", "E_AG", "string（space-delimited integers）", "AT",
  "例示値 \"3 9\"。値の意味表は 11/13 のみ掲載。", writer=DER, authz="補助のみ", syn="G-tenant")
R(E, "xms_par_app_azp", "委任・行為者", "authorized party（azp/appid）の親アプリ。含まれる場合、行為中のエージェント identity に紐づく agent identity blueprint の GUID。", "E_AG", "string（GUID）", "AT",
  "監査ログに記録せよ。認可判断に使うのは非推奨（多数のエージェントに広くアクセスを与えるため）。", writer=DER, authz="不可（表示・監査用）", syn="G-actor")
R(E, "xms_idrel", "識別子", "主体とリソーステナントの関係。空白区切りの奇数整数の多値（1=Member user, 3=MSA member, 5=Guest, 7=Service principal, 9=Device principal, 11=GDAP user, 13=SPLess application, 15=Passthrough, … 33=Federated managed identity）。", "E_AG", "string（space-delimited integers）", "AT",
  "Agent ID 文書で定義。自律エージェントは 7、OBO/エージェントユーザーアカウントは 1 など。", writer=DER, authz="補助のみ", vocab="標準で列挙（Entra Agent ID 文書、1〜33 の奇数）", syn="G-user-type")
R(E, "xms_ftd", "その他", "Agent ID のサンプル AT に現れるクレーム。文書に意味の説明はない。", "E_AG", "string", "AT",
  "サンプル値のみで定義なし。依存しないこと。xms_ で始まるため restricted。", writer="不明", syn="G-internal")
R(E, "deviceid", "端末・ネットワーク・場所", "claims mapping の JWT restricted claim set に名前のみ掲載。発行条件・意味は今回開いた文書に記載なし。", "E_MAP", "不明", "その他（restricted 名として列挙のみ）",
  "一般公開のクレームリファレンスに定義なし。restricted claim set（変更不可）として存在のみ確認。", own="不明", writer="不明", pii="仮名の識別子", syn="G-device")
R(E, "puid", "識別子", "claims mapping の JWT restricted claim set に名前のみ掲載（home_puid も同様）。意味・発行条件は記載なし。", "E_MAP", "不明", "その他（restricted 名として列挙のみ）",
  "SAML restricted: http://schemas.microsoft.com/identity/claims/puid。クレームリファレンスには未掲載。", own="不明", writer="不明", pii="仮名の識別子", syn="G-user-id")

# ============================ Keycloak ============================
K = "K"
R(K, "typ", "トークン種別・メタ", "Keycloak のトークンに含まれるトークン種別クレーム。lightweight AT からも削除できないクレームとして列挙される。", "KC_A", "string", "両方",
  "値（例: Bearer / ID）は今回開いた文書に明記なし（不明）。JOSE ヘッダーの typ とは別のペイロードクレーム。lightweight AT でも必ず残る: exp, iat, jti, iss, typ, azp, sid, scope, cnf。", writer=ISS, syn="G-token-type", sup={"Cognito": "独自の名前で"})
R(K, "azp", "クライアント・ワークロード", "トークンを要求したクライアントの client ID（token exchange 例では requester-client）。", "KC_T", "string", "両方",
  "lightweight AT から削除不可。token exchange 後は交換を要求したクライアントになる。", is_custom=STD, extra_src="Server Admin Guide (lightweight access token)", writer=ISS, authz="iss・aud などと組で可", syn="G-client-id")
R(K, "sub", "識別子", "利用者 ID（例示は UUID 形式）。basic クライアントスコープの Subject (sub) マッパーで付与され、Pairwise subject identifier マッパーで上書き可能。", "KC_U", "string", "両方",
  "Keycloak 25+: AT の sub はマッパー経由（AT・lightweight AT・introspection のみ制御可、ID トークンと UserInfo には常に入る）。service account では常に付与。basic スコープ名が既存と衝突すると移行されず sub/auth_time が欠落し得る。", is_custom=STD, extra_src="Server Admin Guide (Pairwise subject identifier mapper)", writer=ISS, pii="仮名の識別子", uniq="発行者内で一意", syn="G-user-id")
R(K, "auth_time", "時刻・寿命", "利用者の認証時刻。basic クライアントスコープの既定マッパーで付与。", "KC_U", "number（NumericDate）", "両方",
  "Keycloak 25 で basic スコープ導入以降、マッパーで制御可能（以前は常時付与）。", is_custom=STD, own="既定", writer=ISS, fresh="該当なし", syn="G-auth_time")
R(K, "sid", "認証の強さ・セッション", "ユーザーセッション ID。不透明な文字列で、以前の UUID ではなくランダムな base64 文字列（24 文字、将来増える可能性）。", "KC_U", "string（不透明）", "両方",
  "lightweight AT から削除不可。transient session（委任トークン等）では通常空。", is_custom=STD, extra_src="Server Admin Guide", writer=ISS, pii="仮名の識別子", syn="G-session")
R(K, "session_state", "認証の強さ・セッション", "sid と同じ値を持っていた旧クレーム。現在はすべてのトークンから削除され、トークンレスポンスのパラメータとしてのみ残る。", "KC_U", "string（不透明）", "両方",
  "Session State (session_state) マッパーを basic などに割り当てると旧動作に戻せる（古い JS アダプタ 24.0.3 以前向け）。", own="設定で追加", status="非推奨", writer=ISS, syn="G-session")
R(K, "nonce", "開示・暗号・検証補助", "認可要求の nonce。Keycloak は OIDC Core に厳密に従い ID トークンにのみ入れる（リフレッシュ時は付けない）。", "KC_U", "string", "ID",
  "以前は AT・RT・ID 全てに入っていた。Nonce backwards compatible マッパーで旧動作に戻せる。", is_custom=STD, own="既定（ID のみ）", writer=CLI, syn="G-nonce")
R(K, "acr", "認証の強さ・セッション", "達成した認証レベル（LoA）。既定 realm クライアントスコープ acr の「acr loa level」マッパーが付与。ACR to LoA Mapping で gold などの名前にも写像。", "KC_A", "string", "両方",
  "ブラウザ Cookie のみ（レベル期限切れ）の SSO では acr=0。claims パラメータで essential 要求した値を満たせなければエラー。URL 改ざん対策として ID トークンの acr を再確認するよう推奨。", is_custom=STD, writer=DER, authz="iss・aud などと組で可", vocab="発行者ごと", syn="G-acr")
R(K, "amr", "認証の強さ・セッション", "認証フローで成功した各 authenticator 実行に設定した参照値の配列。Authentication Method Reference (AMR) マッパーを設定したクライアントでのみ付与。", "KC_A", "array of string", "両方",
  "値は管理者が authenticator 実行に設定する reference value（RFC 8176 参照と記載）。", is_custom=STD, own="設定で追加", writer=DER, vocab="発行者ごと", syn="G-amr")
R(K, "aud", "発行者・宛先", "トークンの宛先。Keycloak は API を自動で含めず、Audience マッパー（Included Client/Custom Audience）または roles スコープの Audience Resolve マッパー（client role を持つクライアントを追加）で付与。", "KC_A", "string or array of string", "AT",
  "無効化・削除されたクライアントは追加されない。lightweight AT では aud が introspection 応答にのみ存在し得る。token exchange では要求クライアントが subject token の aud に必要。", is_custom=STD, extra_src="Token exchange guide", own="設定で追加", writer=DER, authz="iss・aud などと組で可", syn="G-audience")
R(K, "scope", "権限・認可", "付与されたクライアントスコープ名（空白区切り）。Include in token scope が ON のスコープのみ含まれる。", "KC_A", "string（space-delimited）", "AT",
  "roles・web-origins などは Include in token scope が OFF で scope に出ない。lightweight AT から削除不可。", is_custom=STD, writer=DER, authz="単独で可", vocab="発行者ごと", syn="G-scope")
R(K, "allowed-origins", "端末・ネットワーク・場所", "クライアントに許可された Web オリジン。web-origins クライアントスコープ（realm 既定）のマッパーが AT に付与。", "KC_A", "array of string", "AT",
  "Keycloak 4.6.0 で roles と共に既定スコープ化。CORS 用途。", writer=DER, authz="補助のみ", syn="G-origins")
R(K, "realm_access", "権限・認可", "realm ロールを roles 配列で持つオブジェクト（{\"roles\":[...]}）。roles クライアントスコープの realm roles マッパーが既定で AT と introspection に付与。", "KC_A", "object（roles: array of string）", "AT",
  "ユーザー割当ロール（グループ・複合ロール展開込み）∩ クライアントの role scope mapping。Token claim name で別名に変更可。単一値設定時は 1 つの値のみ（旧版は文字列化 JSON 配列）。", writer=DER, authz="単独で可", vocab="発行者ごと", syn="G-roles")
R(K, "resource_access", "権限・認可", "クライアントロールをクライアント ID ごとに持つオブジェクト（{\"<client>\":{\"roles\":[...]}}）。client roles マッパーが既定で付与。", "KC_A", "object", "AT",
  "無効化・削除クライアントのロールは出ない。token exchange の audience 指定で対象外クライアントのロールはフィルタされる。", writer=DER, authz="単独で可", vocab="発行者ごと", syn="G-roles")
R(K, "groups", "権限・認可", "Group Membership マッパーで付与するグループ所属（Full group path 有効時は /Organization/Admins のようなフルパス）。microprofile-jwt スコープでは realm ロールマッパーが groups を出す。", "KC_U", "array of string", "両方",
  "Full group path 無効でネストグループを対象にするグループポリシーは、フルパスを有効にせよ（最新版で裸名はトップレベルのみに解決）。", is_custom=STD, extra_src="Server Admin Guide (microprofile-jwt scope)", own="設定で追加", writer=DER, authz="単独で可", vocab="発行者ごと", syn="G-groups")
R(K, "upn", "識別子", "microprofile-jwt クライアントスコープのユーザープロパティマッパーが付与する MicroProfile JWT Auth の upn。", "KC_A", "string", "両方",
  "マッパーで元プロパティを変更可。MicroProfile 仕様由来（IETF/OIDF 標準ではない）。", own="設定で追加", writer=DIR, pii="直接識別できる個人情報", syn="G-username")
R(K, "organization", "組織・テナント", "Organizations 機能の所属組織情報。organization スコープ要求時に Organization Membership マッパーが付与。組織 alias をキーに id・属性・groups・ロールを入れ得る。", "KC_A", "object（または alias の配列）", "両方",
  "既定では id と属性は含まれず Add organization id / attributes を有効化。scope=organization（単一）/ organization:* / organization:<alias>。Organization Group Membership マッパー併用で groups（組織相対パス）、Add group role mappings で組織内 realm_access/resource_access。id という名のカスタム属性は組織 ID で上書きされる。", own="設定で追加", writer=DER, authz="iss・aud などと組で可", syn="G-tenant")
R(K, "client_id", "クライアント・ワークロード", "client credentials グラントで service_account クライアントスコープのマッパー（Client Id）が付与するクライアント ID。", "KC_U", "string", "AT",
  "旧 clientId から client_id に変更（RFC 9068 / 7662 / 8693 準拠）。clientId ユーザーセッションノートは存続。サービスアカウント有効時に自動割当。委任では act/may_act 内にも出る。", is_custom=STD, own="既定（service account のみ）", writer=ISS, authz="iss・aud などと組で可", syn="G-client-id")
R(K, "clientHost", "端末・ネットワーク・場所", "service account の認証元デバイスのリモートホスト名。service_account スコープのマッパーが付与。", "KC_U", "string", "AT",
  "client credentials 時のみ。ユーザーセッションノートとして定義。", own="既定（service account のみ）", writer=ISS, syn="G-ip")
R(K, "clientAddress", "端末・ネットワーク・場所", "service account の認証元デバイスのリモート IP。service_account スコープのマッパー（Client IP Address）が付与。", "KC_U", "string", "AT",
  "client credentials 時のみ。", own="既定（service account のみ）", writer=ISS, pii="不明", syn="G-ip")
R(K, "may_act", "委任・行為者", "委任（delegation:user / delegation:client スコープ）で、指定アクターが主体の代理を許可されたことを示す。sub（アクターのユーザー ID または service account ユーザー ID）と client_id を含む。", "KC_T", "object", "両方",
  "Keycloak 26.8 で preview（--features=token-exchange-delegation）。利用者の同意画面と FGAP V2 の delegate 権限が必要。may_act 内で Keycloak が検証するのは sub・client_id・iss のみで他は act にそのまま複写。Parameterized Scope User Property / Hardcoded claim マッパーで may_act.* を追加可。standard token exchange は委任クレーム付き subject token を拒否（26.8 告知）。", is_custom=STD, own="設定で追加", status="プレビュー", writer=DER, syn="G-actor")
R(K, "act", "委任・行為者", "委任交換で発行されたトークンの実行者（アクター）。{\"sub\":<actor のユーザー ID>,\"client_id\":<actor client>} 等。", "KC_T", "object", "AT",
  "26.8 preview。transient session（AT のみ、RT なし）。aud とスコープは actor client の設定から解決（元トークンからではない）。may_act の追加クレームは認可判断に使わず識別用。", is_custom=STD, own="設定で追加", status="プレビュー", writer=DER, authz="補助のみ", syn="G-actor")
R(K, "cnf", "鍵・送信者制約", "送信者制約（DPoP / mTLS）トークンの確認クレーム。lightweight AT でも削除不可。", "KC_A", "object", "AT",
  "Keycloak は送信者制約トークンを別クライアント文脈で交換しない（最新版の変更）。", is_custom=STD, writer=DER, syn="G-cnf")
R(K, "（Hardcoded claim マッパー：任意名）", "その他", "Hardcoded claim マッパーで固定値の任意クレームを追加する。ドット記法でネスト（例 may_act.custom_value）。", "KC_T", "string ほか（設定による）", "両方",
  "Add to ID token / access token / lightweight access token / introspection を個別に切替。マッパーの作成・変更は manage-realm 権限が必要（委任管理者は Allowed protocol mapper types で許可された型のみ）。DCR では既定でマッパー不可。", extra_src="Server Admin Guide (Mappers tab)", own="設定で追加", writer=ISS, syn="G-custom-attr")
R(K, "（User Attribute / User Property マッパー：任意名）", "その他", "ユーザー属性・プロパティを任意名のクレームに写像する。Aggregate attributes でグループ属性も合成可能。", "KC_A", "string または array（Multivalued 設定）", "両方",
  "ユーザープロファイル設定次第で利用者自身が編集できる属性もあるため認可に使う場合は注意（属性の編集権限は文書の User Profile 章で設定）。", own="設定で追加", writer="不明", syn="G-custom-attr")
R(K, "（User Session Note マッパー：任意名）", "認証の強さ・セッション", "ユーザーセッションノート（identity_provider, identity_provider_identity, IMPERSONATOR_ID, IMPERSONATOR_USERNAME, clientId 等）をクレームに写像する。", "KC_A", "string", "両方",
  "identity_provider = ブローカーした IdP の alias、identity_provider_identity = 外部 IdP 側ユーザー名（Keycloak ユーザー名と異なり得る）。なりすまし（impersonation）セッションでは IMPERSONATOR_ID / USERNAME。クレーム名は管理者設定。", own="設定で追加", writer=DER, syn="G-idp")
R(K, "（Script マッパー：任意名）", "その他", "デプロイした JavaScript でクレームを生成する。", "KC_A", "任意", "両方",
  "JavaScript Providers としてデプロイが必要。マッパー優先順位で roles・aud 解決後に実行。", own="フック・式で可", writer="不明", syn="G-custom-attr")
R(K, "（gss delegation credential マッパー）", "鍵・送信者制約", "Kerberos/SPNEGO 認証時の GSS 委任資格情報をシリアライズしてトークンに入れる組み込みマッパー。", "KC_A", "string（シリアライズ済み資格情報）", "AT",
  "クレーム名は KerberosConstants.GSS_DELEGATION_CREDENTIAL 定数（具体文字列は文書に明記なし）。機微な資格情報を含む。", own="設定で追加", writer=DER, pii="機微な個人情報", log="記録しない", syn="G-credential")

# ============================ Auth0 ============================
A = "A"
R(A, "sub", "識別子", "Auth0 の user_id（形式 {identity provider id}|{unique id in the provider}、例 auth0|123456, facebook|1234567890）。M2M（client credentials）では <client_id>@clients、エージェント連携 M2M では agent_id / external_agent_id。", "A0_P", "string", "両方",
  "テナント内で一意。複数テナントで同じ値の保証なし。DB 接続間で ID 衝突を避けるため接続プレフィックス推奨。Agent subject claims 有効の API では @clients 接尾辞なし。", is_custom=STD, extra_src="Identify Users", writer=DER, pii="仮名の識別子", uniq="発行者内で一意", syn="G-user-id")
R(A, "aud", "発行者・宛先", "AT の受信者。audience に API Identifier を指定すると JWT AT になり、openid 付きなら [API, https://<tenant>/userinfo] の配列。ID トークンでは client ID。", "A0_P", "string or array of string", "両方",
  "audience 未指定は /userinfo 用 opaque AT（研究ノート: Get Access Tokens）。カスタムクレームを読むには JWT と aud が必要。", is_custom=STD, extra_src="ID Token Structure", writer=DER, authz="iss・aud などと組で可", syn="G-audience")
R(A, "azp", "クライアント・ワークロード", "Auth0 プロファイル AT で AT を要求したアプリの client ID。", "A0_P", "string", "AT",
  "RFC 9068 プロファイルでは client_id を使い azp は出ない。OBO 交換では外側の act.sub と一致するべき。カスタム追加不可（restricted）。", is_custom=STD, writer=ISS, authz="iss・aud などと組で可", syn="G-client-id")
R(A, "client_id", "クライアント・ワークロード", "RFC 9068 プロファイル AT で AT を要求したアプリの client ID。", "A0_P", "string", "AT",
  "Auth0 プロファイル（既定）では出ない（azp）。", is_custom=STD, own="設定で追加", writer=ISS, authz="iss・aud などと組で可", syn="G-client-id")
R(A, "jti", "トークン種別・メタ", "AT の一意識別子。RFC 9068 プロファイルのみ。", "A0_P", "string", "AT",
  "Auth0 プロファイル（既定）の AT には jti がない。", is_custom=STD, own="設定で追加", writer=ISS, uniq="全体で一意", syn="G-token-id")
R(A, "gty", "トークン種別・メタ", "AT 取得に使ったグラント種別（client-credentials, password, refresh_token の場合のみ）。", "A0_P", "string", "AT",
  "Auth0 プロファイル独自。RFC 9068 プロファイルでは出ない。カスタム追加不可。", own="既定（Auth0 プロファイル AT のみ）", writer=ISS, authz="補助のみ", vocab="発行者ごと", syn="G-grant-type")
R(A, "scope", "権限・認可", "発行された AT のスコープ（空白区切り）。要求スコープとユーザー権限の積。", "A0_P", "string（space-delimited）", "AT",
  "RBAC 有効時、scope は要求 ∩ 付与権限（RBAC 文書）。", is_custom=STD, extra_src="Enable RBAC for APIs", writer=DER, authz="単独で可", syn="G-scope")
R(A, "permissions", "権限・認可", "RBAC 有効 + Add Permissions in the Access Token で、ユーザーに割り当てられた全権限を列挙する配列。", "A0_RBAC", "array of string", "AT",
  "トグルで dialect が access_token→access_token_authz、rfc9068_profile→rfc9068_profile_authz に変わる。トークンサイズが増える。カスタムクレーム名として素の permissions は使えない。", extra_src="Access Token Profiles", own="設定で追加", writer=DER, authz="単独で可", vocab="発行者ごと", syn="G-roles")
R(A, "org_id", "組織・テナント", "Organization 経由で認証したときの組織 ID（例 org_9ybsU1dN2dKfDkBi）。既定で ID・AT に含まれる。", "A0_ORG", "string", "両方",
  "organization パラメータなしで org_id がある場合も既知の値か検証、検証できなければトークン無効扱い。API は org_id でデータを分離。名前より ID での検証を推奨。OBO 交換でも維持。第三者アプリは ID トークンを受け取らない。", extra_src="Access Token Profiles", writer=ISS, mut="不変", authz="iss・aud などと組で可", uniq="発行者内で一意", syn="G-tenant")
R(A, "org_name", "組織・テナント", "組織名。テナントで Organization Names in Authentication API を有効にしたときのみ org_id と共に入る。", "A0_ORG", "string", "両方",
  "組織名は改名・再利用され得て、長寿命トークンの org_name は旧値のまま→別組織に誤ってアクセスを与える恐れ。テナント内でのみ一意。存在すれば org_id と併せて検証。", own="設定で追加", writer=DIR, mut="改名・変更あり", authz="補助のみ", uniq="発行者内で一意", syn="G-tenant")
R(A, "authorization_details", "同意・目的・取引", "Rich Authorization Requests（RAR）で使われた認可詳細。", "A0_P", "array of object", "AT",
  "Case-specific（RAR 利用時）。restricted claim でカスタム追加不可。", is_custom=STD, own="設定で追加", writer=CLI, syn="G-authz-details")
R(A, "cnf", "鍵・送信者制約", "mTLS トークンバインディングの確認クレーム（例 {\"x5t#S256\":...}）。", "A0_P", "object", "AT",
  "Case-specific。Agent as Principal の act 内では DPoP バインディング用 cnf が入ることがある。", is_custom=STD, own="設定で追加", writer=DER, syn="G-cnf")
R(A, "sub_profile", "委任・行為者", "主体の実体種別（user, ai_agent, service, browser_app, native_app）。", "A0_G", "string", "AT",
  "Agent as Principal（Early Access）。リソースサーバーで agent_subject_claims: 'auth0-v1' をオプトインし、エージェント連携クライアントが関与したときのみ。AT のみで ID トークンは不変。常に user と仮定しないこと。OAuth Actor Profile for Delegation 草案を採用と記載。", extra_src="Access Token Profiles", own="設定で追加", status="プレビュー", writer=DER, authz="補助のみ", vocab="標準で列挙（Auth0 文書: user/ai_agent/service/browser_app/native_app）", syn="G-subject-type")
R(A, "client_profile", "委任・行為者", "要求クライアントの実体種別。空白区切りで複数可（例 \"service ai_agent\"）。", "A0_G", "string（space-delimited）", "AT",
  "sub_profile と同条件（Early Access）。", extra_src="Access Token Profiles", own="設定で追加", status="プレビュー", writer=DER, authz="補助のみ", vocab="標準で列挙（Auth0 文書）", syn="G-subject-type")
R(A, "act", "委任・行為者", "RFC 8693 のアクタークレーム。OBO 交換では外側の act.sub が現在のアクター（交換したクライアント）で、以前のチェーンはネストした act に保持。Agent as Principal では sub, iss, sub_profile, client_id, client_profile, cnf を含み得る。", "A0_O", "object", "AT",
  "OBO: sub（利用者）は維持、aud は下流 API。委任チェーンは 5 レベルまで（subject token に既に 4 レベルあると失敗、エラー文言は上限 4）。Agent as Principal は Early Access。カスタムクレーム名として act は使えない。", is_custom=STD, extra_src="Agent identity in tokens", own="設定で追加", writer=DER, authz="補助のみ", limit="ネスト 5 レベル（既に 4 レベルで交換失敗）", syn="G-actor")
R(A, "（namespaced カスタムクレーム）", "その他", "Actions の api.idToken / api.accessToken.setCustomClaim で追加する衝突耐性のある名前空間付きクレーム（例 https://myapp.example.com/roles）。", "A0_C", "任意（JSON）", "両方",
  "名前空間は自分が管理する非 Auth0 の HTTP(S) URL（auth0.com, webtask.io, webtask.run 不可）またはカスタム API なら URN（urn:auth0 は予約）。URL は識別子でアクセスされない。カスタムクレーム合計 100KB。衝突時はトランザクションは失敗せずクレームが黙って追加されない。", own="フック・式で可", writer="不明", limit="カスタムクレームペイロード最大 100KB。衝突時は黙って追加されない", syn="G-custom-attr")
R(A, "（non-namespaced カスタムクレーム）", "その他", "名前空間なしのカスタムクレーム（例 employee_id）。許可されるが制約あり。", "A0_C", "任意（JSON）", "両方",
  "Auth0 API audience を持つ AT（/userinfo 除く）には private な non-namespaced クレームを入れられない。restricted 名（acr, act, active, amr, at_hash, ath, attest, aud, auth_time, authorization_details, azp, c_hash, client_id, cnf, cty, dest, entitlements, events, exp, groups, gty, htm, htu, iat, internalService, iss, jcard, jku, jti, jwe, jwk, kid, may_act, mky, nbf, nonce, object_id, org_id, org_name, orig, origid, permissions, roles, rph, s_hash, sid, sip_*, sub, sub_jwk, toe, txn, typ, uuid, vot, vtm, x5t#S256）は不可。OIDC プロフィールクレームのうち指定されたもののみ AT に追加可。", own="フック・式で可", writer="不明", limit="合計 100KB", syn="G-custom-attr")

# ============================ Okta ============================
O = "O"
R(O, "ver", "トークン種別・メタ", "トークンのセマンティックバージョン（integer、例 1）。", "OK_R", "number（integer）", "両方",
  "AT・ID 両方の予約クレーム。Entra の ver（\"1.0\"/\"2.0\" 文字列）とは型・意味が違う。", writer=ISS, syn="G-token-version", sup={"Entra": "独自の名前で"})
R(O, "cid", "クライアント・ワークロード", "AT を要求したクライアントの client ID。", "OK_R", "string", "AT",
  "予約クレーム（上書き不可）。", writer=ISS, authz="iss・aud などと組で可", syn="G-client-id")
R(O, "uid", "識別子", "利用者の一意 ID（例 00u...）。ユーザーに紐づかない AT には含まれない。", "OK_R", "string", "AT",
  "予約クレーム。AT の sub は環境・フローでログイン名になり得るため、AT で利用者をキーにするなら uid（token exchange 例で sub=user@example.com, uid=00u...）。", extra_src="Set up OAuth 2.0 On-Behalf-Of Token Exchange (example)", writer=ISS, pii="仮名の識別子", uniq="発行者内で一意", syn="G-user-id")
R(O, "scp", "権限・認可", "AT に付与されたスコープの配列。", "OK_R", "array of string", "AT",
  "予約クレーム。Entra の scp（空白区切り文字列）、RFC 9068 の scope（文字列）と型が違う。カスタムスコープ名に < と > を同時に含められない。scope パラメータ最大 1024 文字。", writer=DER, authz="単独で可", vocab="発行者ごと", limit="scope パラメータ値最大 1024 文字", syn="G-scope", sup={"Entra": "独自の名前で"})
R(O, "sub", "識別子", "主体。ID トークンでは Okta ユーザー ID（00u...）。AT はリファレンスの例では 00u... だが、token exchange ガイドの例ではログイン名（user@example.com）。", "OK_R", "string", "両方",
  "AT の sub の形式は文書間で例が一致しない（予約 AT クレーム表に sub の定義なし）。AT では uid を使うのが安全（推論ではなく uid の定義「利用者の一意 ID」に依拠）。", is_custom=STD, extra_src="Set up OAuth 2.0 On-Behalf-Of Token Exchange (example)", writer=ISS, pii="仮名の識別子", syn="G-user-id")
R(O, "idp", "認証の強さ・セッション", "Okta org ID、またはソーシャル認証・Inbound SAML の場合はその Identity Provider の ID。", "OK_R", "string", "ID",
  "ID トークンの base claim（常に存在）。Entra の idp（STS URI）とは値の形式が違う。", writer=ISS, authz="補助のみ", syn="G-idp", sup={"Entra": "既定"})
R(O, "amr", "認証の強さ・セッション", "認証で使われた方法の識別子配列（例 pwd, mfa, otp, kba, sms, swk, hwk）。", "OK_R", "array of string", "ID",
  "ID トークンの base claim。kba など RFC 8176 にない値を含む。", is_custom=STD, own="既定（ID のみ）", writer=ISS, vocab="発行者ごと", syn="G-amr")
R(O, "acr", "認証の強さ・セッション", "認証時に利用者が検証した保証レベルの情報。", "OK_R", "string", "AT",
  "AT の予約クレーム。値の形式は今回開いたページに記載なし。", is_custom=STD, own="既定（AT）", writer=ISS, vocab="不明", syn="G-acr")
R(O, "auth_time", "時刻・寿命", "エンドユーザーの認証時刻。", "OK_R", "number（integer）", "両方",
  "AT の予約クレームかつ ID トークンの base claim。", is_custom=STDK, writer=ISS, fresh="該当なし", syn="G-auth_time")
R(O, "jti", "トークン種別・メタ", "デバッグ・失効用のトークン一意 ID（例 AT.… / ID.… の接頭辞付き）。", "OK_R", "string", "両方",
  "AT・ID 両方に既定。例示値は AT. / ID. で始まる。", is_custom=STD, writer=ISS, uniq="全体で一意", syn="G-token-id")
R(O, "aud", "発行者・宛先", "ID トークンはクライアント ID。AT は Custom AS に設定した audience（例 https://api.example.com、api://default）。", "OK_R", "string", "両方",
  "Org AS の AT は Okta 専用で自前 API で検証しない（研究ノート）。audiences に \":\" を含む場合は有効な URI。", is_custom=STD, extra_src="Set up token exchange", writer=DER, authz="iss・aud などと組で可", syn="G-audience")
R(O, "iss", "発行者・宛先", "認可サーバーインスタンスの一意識別子。Custom AS は https://{yourOktaDomain}/oauth2/{authorizationServerId}、Org AS は https://{yourOktaDomain}。", "OK_R", "string（URL）", "両方",
  "Org AS と Custom AS で iss が異なる（取り違え注意）。", is_custom=STD, writer=ISS, authz="iss・aud などと組で可", syn="G-issuer")
R(O, "groups", "権限・認可", "アプリのグループフィルタ（regex 等）または式に一致する利用者のグループ名のリスト。groups スコープで要求。", "OK_R", "array of string", "両方",
  "上限 100: 100 を超えて一致すると要求自体が失敗（将来変更あり）。Org AS は ID トークンのみに groups を追加可（AT 不可）、thin ID トークン（Implicit 等）は base claims のみ。Custom AS は AT/ID に Always/要求時で追加。Okta 以外由来のグループは式が必要。", is_custom=STD, extra_src="Customize tokens with a groups claim", own="設定で追加", writer=DER, authz="単独で可", limit="100 件超で要求失敗", vocab="発行者ごと", syn="G-groups")
R(O, "act", "委任・行為者", "On-Behalf-Of Token Exchange で主体の代理として行動した当事者。既存の act は act.act にネストして委任チェーンを保持。", "OK_R", "object", "AT",
  "AT の予約クレーム。チェーンは最大 5 アクター。token exchange 例では act.sub がクライアント ID（0oa…）。", is_custom=STD, extra_src="Set up token exchange", own="設定で追加", writer=DER, limit="最大 5 アクター", syn="G-actor")
R(O, "（Custom AS のカスタムクレーム：Okta Expression Language）", "その他", "Custom AS で定義する任意名のクレーム。値は Groups filter または Okta Expression Language（user.*, app.profile.* 等）で生成。", "OK_C", "任意", "両方",
  "式は最大 1024 文字。Include in token type（ID / AT）、Always / 要求時、Include in（任意スコープ / 指定スコープ）。予約クレームは上書き不可。Org AS では groups 以外のカスタムクレーム不可。ID トークンに入らなくても /userinfo は全クレームを返す。", own="設定で追加", writer=DER, limit="式 1024 文字", syn="G-custom-attr")

# ============================ Amazon Cognito ============================
C = "C"
R(C, "token_use", "トークン種別・メタ", "トークンの用途。ID トークンは \"id\"、アクセストークンは \"access\"。", "CG_ID", "string（id | access）", "両方",
  "必ず検証: AT のみ受理する API で token_use=access を確認しないと ID トークンが通る。", extra_src="Understanding the access token", writer=ISS, authz="iss・aud などと組で可", vocab="標準で列挙（id/access）", cmp="大小区別の完全一致", syn="G-token-type", sup={"Keycloak": "独自の名前で"})
R(C, "sub", "識別子", "利用者の一意 ID（Cognito 独自形式で RFC UUID に準拠しない）。username はプール内一意と限らず sub が最良の識別手段。M2M AT では要求した app client の ID（client_id と同値）。", "CG_ID", "string", "両方",
  "sub の形式を厳密検証しない。Pre token generation で変更不可。", is_custom=STD, extra_src="Understanding the access token", writer=ISS, mut="不変", pii="仮名の識別子", uniq="発行者内で一意", syn="G-user-id")
R(C, "cognito:username", "識別子", "ユーザープール内の利用者のユーザー名（ID トークン）。", "CG_ID", "string", "ID",
  "プール内で一意とは限らないため識別キーにしない（sub を使う）。Pre token generation で変更不可。", writer=ISS, pii="直接識別できる個人情報", syn="G-username")
R(C, "username", "識別子", "ユーザープール内の利用者のユーザー名（アクセストークン）。", "CG_AT", "string", "AT",
  "M2M AT には含まれない。変更不可（PTG v2/v3）。RFC 7662 の username（introspection 応答）とは別定義。", writer=ISS, pii="直接識別できる個人情報", syn="G-username")
R(C, "cognito:groups", "権限・認可", "利用者が所属するユーザープールグループ名の配列（1 つでも配列）。", "CG_ID", "array of string", "両方",
  "M2M AT には含まれない。PTG の groupsToOverride で置換、claimsToSuppress で抑止可（全バージョン）。ユーザーあたりグループ所属上限 100（研究ノート: quotas）。", extra_src="Pre token generation (claims reference)", writer=DER, authz="単独で可", limit="ユーザーあたり 100 グループ（quotas）", vocab="発行者ごと", syn="G-groups",
  sup={"Entra": "独自の名前で", "Keycloak": "独自の名前で", "Okta": "独自の名前で"})
R(C, "cognito:roles", "権限・認可", "利用者のグループに紐づく全 IAM ロール ARN の配列（優先度に関係なく）。", "CG_ID", "array of string（ARN）", "ID",
  "PTG iamRolesToOverride で変更、抑止は cognito:groups を claimsToSuppress に入れる。", extra_src="Pre token generation", writer=DER, authz="補助のみ", syn="G-roles")
R(C, "cognito:preferred_role", "権限・認可", "利用者の最優先グループに関連付けた IAM ロールの ARN（単一文字列）。", "CG_ID", "string（ARN）", "ID",
  "グループの precedence で選択。PTG preferredRole で変更。Identity pool でのロール選択に使われる。", extra_src="Pre token generation", writer=DER, authz="補助のみ", syn="G-roles")
R(C, "（その他の cognito: 接頭辞クレーム）", "その他", "cognito: で始まるその他のクレームは Cognito 予約。", "CG_PTG", "不明", "その他（予約）",
  "Pre token generation で追加・変更・抑止すべて不可。", own="不明", writer=ISS, syn="G-reserved")
R(C, "iss", "発行者・宛先", "トークンを生成したユーザープール。形式 https://cognito-idp.<Region>.amazonaws.com/<user pool ID>。original / updated issuer の 2 種がある。", "CG_ID", "string（URL）", "両方",
  "updated issuer はマルチリージョンで同一 JWKS（URL 形式の詳細は未確認）。", is_custom=STD, writer=ISS, authz="iss・aud などと組で可", syn="G-issuer")
R(C, "aud", "発行者・宛先", "ID トークン: 利用者を認証した app client ID（AT の client_id と同値）。AT: resource binding（RFC 8707 resource パラメータ）を要求したときのみ、認可対象 API の URL。", "CG_ID", "string", "両方",
  "AT には既定で aud がない（client_id を検証）。PTG で AT に aud を追加できるが値は現在のセッションの app client ID と一致必須。token exchange は単一 audience に束縛。", is_custom=STD, extra_src="Understanding the access token; Pre token generation", writer=DER, authz="iss・aud などと組で可", syn="G-audience")
R(C, "client_id", "クライアント・ワークロード", "利用者を認証した user pool app client（AT）。ID トークンの aud と同値。M2M では sub と同値。", "CG_AT", "string", "AT",
  "Pre token generation で変更不可。AgentCore Inbound JWT authorizer の allowed clients は client_id と照合（研究ノート）。", is_custom=STD, writer=ISS, authz="iss・aud などと組で可", syn="G-client-id")
R(C, "scope", "権限・認可", "利用者に発行された OAuth 2.0 スコープ（空白区切り）。API サインインで得た AT は aws.cognito.signin.user.admin のみ。", "CG_AT", "string（space-delimited）", "AT",
  "PTG v2/v3 の scopesToAdd / scopesToSuppress で変更。aws.cognito.signin.user.admin は利用者自身の属性読み書き等を許す。", is_custom=STD, extra_src="Pre token generation", writer=DER, authz="単独で可", vocab="発行者ごと", syn="G-scope")
R(C, "origin_jti", "監査・相関・イベント", "利用者の refresh token に紐づくトークン失効識別子。RevokeToken / Revoke エンドポイントで同じ origin_jti の AT・ID トークンを無効化。", "CG_ID", "string", "両方",
  "M2M AT には含まれない。失効は署名・exp だけでは検出できず Cognito 側の確認が必要（研究ノート）。", extra_src="Understanding the access token", writer=ISS, authz="補助のみ", fresh="都度照会が必要", syn="G-revocation")
R(C, "event_id", "監査・相関・イベント", "認証イベントの識別子（例示は UUID 形式）。", "CG_ID", "string", "両方",
  "Pre token generation で変更不可。ページに詳細な定義説明はない。", extra_src="Understanding the access token; Pre token generation", writer=ISS, syn="G-event-id")
R(C, "identities", "識別子", "利用者にリンクされた外部 IdP プロフィールの配列。各要素は userId, providerName, providerType, issuer, primary, dateCreated（すべて文字列）。", "CG_ID", "array of object", "ID",
  "primary は文字列 \"true\"/\"false\"（JSON boolean ではない）、dateCreated はミリ秒 Unix 時刻の文字列、issuer は null 可。1 件でも配列。変更不可。", writer=DIR, pii="仮名の識別子", syn="G-idp")
R(C, "sid", "認証の強さ・セッション", "トークンセッション ID。セッショントラッキング有効時のみ。リフレッシュ・ローテーションでも同値で ListUserSessions の SessionId と一致。", "CG_ID", "string", "両方",
  "M2M AT には含まれない。セッショントラッキング有効時は PTG での sid 追加・上書きは拒否される。", is_custom=STD, own="設定で追加", extra_src="Understanding the access token; Pre token generation", writer=ISS, pii="仮名の識別子", syn="G-session")
R(C, "device_key", "端末・ネットワーク・場所", "記憶されたユーザーデバイスの識別子。", "CG_AT", "string", "AT",
  "M2M AT には含まれない。PTG で変更不可。", writer=ISS, pii="仮名の識別子", syn="G-device")
R(C, "version", "トークン種別・メタ", "AT のバージョン（例 2）。", "CG_AT", "number", "AT",
  "Pre token generation で変更不可。意味の説明はページにない。", writer=ISS, syn="G-token-version")
R(C, "nonce", "開示・暗号・検証補助", "authorize 要求の nonce。指定がない場合でも、外部 IdP 経由の認証では Cognito が自動生成・検証して ID トークンに入れる。", "CG_ID", "string", "ID",
  "クライアント未指定時の自動生成は Cognito 固有の挙動。", is_custom=STD, writer=CLI, syn="G-nonce")
R(C, "acr", "認証の強さ・セッション", "利用者が満たした認証レベル。固定 4 レベル（既定 URI urn:cognito:loa:1〜4、名前のみ AcrConfiguration で変更可）。", "CG_STEP", "string（URI）", "両方",
  "段階的ロールアウト中で未提供のプールあり。1=パスワードのみ、2=SMS/メール OTP 単独、3=パスキー単独またはパスワード+SMS/メール OTP、4=パスワード+TOTP。連携ユーザーは IdP 応答から AcrMapping で導出。リフレッシュ後も維持。PTG で変更不可。NIST/eIDAS への対応付けはアプリ責務。", is_custom=STD, extra_src="Pre token generation", own="既定（段階展開中）", writer=DER, authz="iss・aud などと組で可", vocab="標準で列挙（urn:cognito:loa:1〜4）", syn="G-acr")
R(C, "amr", "認証の強さ・セッション", "完了した認証方式の配列（pwd, otp, sms, email_otp, swk, hwk, mfa, fed）。", "CG_STEP", "array of string", "両方",
  "otp は TOTP、email_otp は Cognito 独自値。fed は ACR/AMR 非対応 IdP 経由のプレースホルダ。段階的ロールアウト中。PTG で変更不可。", is_custom=STD, own="既定（段階展開中）", writer=DER, vocab="標準で列挙（Cognito 文書）", syn="G-amr")
R(C, "act", "委任・行為者", "Token exchange（2026-11-12 追加、Essentials/Plus）で actor token を提示した場合に、利用者の代理として行動する仲介者を示す RFC 8693 の act。identity claims のみを含む。", "CG_TE", "object", "AT",
  "actor token なしでは act なし＝利用者本人と区別不能。may_act は発行も評価もしない。発行トークンはスコープ＝要求∩subject token∩app client 許可、単一 audience・resource、RT なし。", is_custom=STD, own="設定で追加", writer=DER, authz="補助のみ", syn="G-actor")
R(C, "custom:<name>", "その他", "ユーザープールのカスタム属性。コード上 custom: 接頭辞付き。ID トークンには常に文字列として書かれる。", "CG_ATTR", "string（型に関わらず文字列）", "ID",
  "最大 50 個、値は最大 2048 文字。追加後は削除・改名・型・可変性・長さ制約の変更不可。immutable は作成時のみ書込可、mutable は app client の書込権限で変更可。PTG で追加・変更・抑止可。", extra_src="Understanding the ID token; Pre token generation", own="設定で追加", writer="本人が編集できる", limit="50 属性・値 2048 文字", syn="G-custom-attr")
R(C, "dev:<name>", "その他", "開発者属性（レガシー）。CreateUserPool の SchemaAttributes で作成し、AWS 認証情報でのみ変更可能。app client の読み書き権限に置き換えられた旧機能。", "CG_ATTR", "string", "ID",
  "PTG では抑止のみ可（追加・変更不可）。", extra_src="Pre token generation", own="設定で追加", status="非推奨", writer=ISS, syn="G-custom-attr")
R(C, "（Pre token generation で追加する任意クレーム）", "その他", "ユーザープールのトークンスキーマにない任意クレームを Lambda の claimsToAddOrOverride で追加・claimsToSuppress で抑止する。", "CG_PTG", "任意（V2 以降は複合オブジェクト可）", "両方",
  "V1_0 = ID トークンのみ（全プラン）、V2_0 = ID+AT（Essentials/Plus）、V3_0 = +M2M AT（Essentials/Plus、M2M は別料金）。既存+追加クレーム+スコープ合計 5,000 のクォータ（研究ノート: quotas）。変更不可: sub, cognito:username, username, client_id, aud（AT は client ID 一致のみ可）, identities, event_id, device_key, version, acr, amr, at_hash, 他の cognito: 接頭辞。", own="フック・式で可", writer="不明", limit="既存+追加クレーム+スコープ合計 5,000（調整可、研究ノート）", syn="G-custom-attr")
R(C, "email_verified", "本人確認・保証", "email 属性が検証済みか。Cognito では利用者または管理者（AdminUpdateUserAttributes で直接 true に設定可）が検証状態を設定できる。", "CG_ATTR", "boolean", "ID",
  "管理者が検証手続きなしに true にできる点が OIDC 標準の想定と異なり得る。検証できるのは email と phone_number のみ。", is_custom=STD, extra_src="Understanding the ID token", writer=ISS, authz="補助のみ", syn="G-email-verified")
R(C, "phone_number_verified", "本人確認・保証", "phone_number が検証済みか。管理者が AdminUpdateUserAttributes で直接 true にできる。", "CG_ATTR", "boolean", "ID",
  "電話番号は + と数字のみの形式（E.164 相当）が必須。", is_custom=STD, writer=ISS, authz="補助のみ", syn="G-phone-verified")

# ---- additional vendor-constraint rows ----
R(O, "exp", "時刻・寿命", "トークンの有効期限（Unix 秒）。Org AS は ID/AT とも 60 分固定、Custom AS の AT は 5 分〜24 時間（アクセスポリシー）、ID トークンは 60 分固定。", "OK_R", "number（integer）", "両方",
  "発行クライアントが無効化されると AT は即時かつ恒久的に無効（再有効化しても戻らない）＝exp 前でも無効になり得る。", is_custom=STD, writer=ISS, fresh="該当なし", syn="G-exp")
R(O, "nonce", "開示・暗号・検証補助", "implicit flow では nonce パラメータ必須で ID トークンに nonce が入り、/authorize に渡した値と一致を検証する。", "OK_R", "string", "ID",
  "Okta 固有の制約: implicit flow で必須。", is_custom=STD, own="既定（ID のみ）", writer=CLI, syn="G-nonce")
R(O, "at_hash", "開示・暗号・検証補助", "ID と AT を同時に要求した場合に ID トークンに入る AT のハッシュ。", "OK_R", "string", "ID",
  "標準と同義。発行条件の記述のみ Okta 固有。", is_custom=STD, own="既定（ID のみ）", writer=DER, syn="G-at_hash")
R(O, "preferred_username", "プロフィール・連絡先", "利用者が選んだログイン名。既定は Okta のユーザー名（例 john.doe@example.com）。", "OK_R", "string", "ID",
  "profile スコープ。id_token token 応答の Org AS ID トークンでは name と preferred_username のみ。", is_custom=STD, own="設定で追加", writer=DIR, mut="改名・変更あり", pii="直接識別できる個人情報", syn="G-username")
R(O, "email", "プロフィール・連絡先", "利用者の優先メールアドレス。リソース提供者は値の一意性に依存してはならない。", "OK_R", "string", "ID",
  "email スコープ。", is_custom=STD, own="設定で追加", writer=DIR, mut="随時変わる", authz="不可（表示・監査用）", pii="直接識別できる個人情報", uniq="なし", syn="G-email")
R(O, "email_verified", "本人確認・保証", "利用者のメール（Okta primary email）が検証済みなら true。", "OK_R", "boolean", "ID",
  "対象は primary email に限定。", is_custom=STD, own="設定で追加", writer=ISS, syn="G-email-verified")
R(O, "phone_number", "プロフィール・連絡先", "利用者の優先電話番号（E.164 形式と記載）。", "OK_R", "string", "ID",
  "記載は E.164 だが例示値は \"+1 (425) 555-1212\" で E.164 ではない。形式を厳密に仮定しない。", is_custom=STD, own="設定で追加", writer=DIR, pii="直接識別できる個人情報", syn="G-phone")
R(A, "iss", "発行者・宛先", "AT を発行した Auth0 テナントの発行者 ID（例 https://tenant.auth0.com/）。", "A0_P", "string（URL）", "両方",
  "例示値は末尾スラッシュ付き。ID トークン例は http://my-domain.auth0.com（スラッシュなし）で表記が揺れる。完全一致比較の前に discovery の issuer を使う。", is_custom=STD, extra_src="ID Token Structure", writer=ISS, cmp="大小区別の完全一致", syn="G-issuer")
R(C, "exp", "時刻・寿命", "トークンの有効期限（Unix 時刻）。ID・AT の期限は app client ごとに 5 分〜1 日。", "CG_ID", "number（NumericDate）", "両方",
  "managed login は 1 時間有効のセッション Cookie を設定するため、1 時間未満の期限でも再認証なしで更新できる。失効（RevokeToken）は exp では検出できない。", is_custom=STD, extra_src="Understanding the access token", writer=ISS, fresh="該当なし", limit="5 分〜1 日", syn="G-exp")
R(C, "email", "プロフィール・連絡先", "email 属性があり app client が読取可能なときの利用者メール。", "CG_ID", "string", "ID",
  "app client の属性読取権限に依存。最大 2048 文字。alias 設定により重複メールの扱いが変わる。", is_custom=STD, own="設定で追加", writer="本人が編集できる", mut="随時変わる", pii="直接識別できる個人情報", syn="G-email")
R(K, "（Audience マッパー）", "発行者・宛先", "Included Client Audience / Included Custom Audience を aud に追加する組み込みマッパー。lightweight AT 向けに Add to lightweight access token を ON にする必要がある場合がある。", "KC_A", "string", "AT",
  "token exchange で lightweight AT を通常 AT に変換するには対象クライアントが aud に必要。", own="設定で追加", writer=ISS, syn="G-audience")
R(K, "（Pairwise subject identifier マッパー）", "識別子", "sub をセクター単位のペアワイズ値で上書きするマッパー。Subject (sub) マッパーの後に実行され値を上書き。", "KC_A", "string", "両方",
  "Subject (sub) マッパーを外す必要は厳密にはない（性能のみ）。", own="設定で追加", writer=DER, pii="仮名の識別子", syn="G-user-id")

json.dump(rows, open(sys.argv[1], "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print(len(rows))
from collections import Counter
print(Counter(r["support"] and [k for k,v in VENDOR.items()] and r["change_controller"] for r in rows))

# -*- coding: utf-8 -*-
import json, sys
V=["Entra","Keycloak","Auth0","Okta","Cognito"]
S={}
def s(c, e,k,a,o,g, note):
    S[c]=dict(zip(V,[e,k,a,o,g])); S[c]["note"]=note
s("iss","既定","既定","既定","既定","既定","Entra は v1/v2 で形式が異なり common/organizations は {tenantid} テンプレート。Okta は Org AS と Custom AS で異なる。Cognito は original/updated issuer。Auth0 は例示で末尾スラッシュ有無が揺れる。")
s("sub","既定","既定","既定","既定","既定","意味が IdP ごとに違う: Entra はアプリごとのペアワイズ（共有キーは oid+tid）、Keycloak は利用者 ID（basic スコープのマッパー、Pairwise マッパーで上書き可）、Auth0 は provider|id（M2M は client_id@clients、エージェントは agent_id）、Okta は ID トークン=ユーザー ID、AT は例によりログイン名、Cognito は独自形式（UUID 検証しない、M2M は client ID）。")
s("aud","既定","設定で追加","既定","既定","既定（ID のみ）","Keycloak の AT は API を自動で含まず Audience / Audience Resolve マッパーが必要（ID トークンの aud は今回未確認）。Auth0 は audience パラメータ指定時のみ JWT AT（openid 付きで配列）。Cognito AT は resource（RFC 8707）指定時のみ aud、通常は client_id。Entra v1 AT は App ID URI の揺れあり（use_guid）。")
s("exp","既定","既定","既定","既定","既定","Okta Org AS は 60 分固定。Cognito は 5 分〜1 日。Entra AT は 60–90 分ランダム（CAE は最大 28h）。")
s("nbf","既定","不明","不明","不明","不明","Entra のみ文書で確認。他は今回のクレーム一覧に記載なし。")
s("iat","既定","既定","既定","既定","既定","Entra 文書は iat を「認証が行われた時刻」と説明しており RFC 7519 の文言と異なる。")
s("jti","独自の名前で","既定","設定で追加","既定","既定","Entra は uti。Auth0 は RFC 9068 プロファイル AT のみ（既定の Auth0 プロファイルには無い）。Okta は AT./ID. 接頭辞付き。")
s("auth_time","設定で追加","既定","不明","既定","既定","Entra は optional claim。Keycloak は basic スコープのマッパー。Auth0 は restricted 名に含まれるが発行条件は未確認。")
s("nonce","既定（ID のみ）","既定（ID のみ）","不明","既定（ID のみ）","既定（ID のみ）","Keycloak は 25 以降 ID トークンのみ（互換マッパーあり）。Okta は implicit で必須。Cognito は外部 IdP 経由で未指定時に自動生成。")
s("acr","既定（AT・v1 のみ）","既定","不明","既定（AT）","既定","Entra は v1.0 AT のみで値 0/1（step-up は acrs）。Keycloak は acr スコープの LoA マッパー（Cookie のみは 0）。Okta は AT の予約クレーム（値形式未確認）。Cognito は urn:cognito:loa:1〜4、段階展開中で変更不可。Auth0 は restricted 名のみ確認。")
s("amr","既定（v1 のみ）","設定で追加","不明","既定（ID のみ）","既定","Entra は v1 既定・v2 は optional claim、独自値語彙。Keycloak は AMR マッパー（authenticator の参照値）。Okta は ID の base claim。Cognito は pwd/otp/sms/email_otp/swk/hwk/mfa/fed、段階展開中。")
s("azp","既定（AT・v2 のみ）","既定","既定（AT・Auth0 プロファイル）","独自の名前で","独自の名前で","Entra の azp は v2 AT のクライアント ID（appid の後継）で OIDC の ID トークン azp と用途が異なる。Okta は cid、Cognito は client_id。Auth0 RFC 9068 プロファイルは client_id。")
s("at_hash","既定（ID のみ）","不明","不明","既定（ID のみ）","既定（ID のみ）","Entra は /authorize から AT と共に発行された場合のみ（/token では無し）。Okta は ID と AT を同時要求時。Cognito は PTG 表で ID トークンの既定クレームとして記載。")
s("c_hash","既定（ID のみ）","不明","不明","不明","不明","Entra は認可コードと共に発行された ID トークンのみ（/token では無し）。")
s("sid","既定","既定","不明","不明","設定で追加","Entra は GUID。Keycloak は base64 の 24 文字（UUID ではない、transient session では空）。Cognito はセッショントラッキング有効時のみ。")
s("scope","独自の名前で","既定（AT）","既定（AT）","独自の名前で","既定（AT）","Entra は scp（空白区切り、ユーザートークンのみ、アプリは roles）。Okta は scp（配列）。Keycloak は Include in token scope のスコープのみ。Cognito API サインインは aws.cognito.signin.user.admin のみ。")
s("client_id","独自の名前で","既定（AT・service account のみ）","設定で追加","独自の名前で","既定（AT）","Entra は appid（v1）/azp（v2）。Okta は cid。Auth0 は RFC 9068 プロファイルのみ（既定は azp）。")
s("groups","設定で追加","設定で追加","フック・式で可","設定で追加","独自の名前で","Entra は groupMembershipClaims、JWT 200 件超で _claim_names に置換。Keycloak は Group Membership マッパー（microprofile-jwt でも groups）。Auth0 は素の groups 名は restricted で namespaced カスタムクレームのみ。Okta は groups スコープ、100 件超で要求失敗、Org AS は ID トークンのみ。Cognito は cognito:groups。")
s("roles","既定","独自の名前で","独自の名前で","フック・式で可","独自の名前で","Entra roles はアプリロール/アプリ許可（割当時に出る）。Keycloak は realm_access.roles / resource_access.<client>.roles。Auth0 は permissions（RBAC）で素の roles は restricted。Okta はカスタムクレームで作る。Cognito の cognito:roles は IAM ロール ARN で意味が違う。")
s("entitlements","不明","不明","不可・未対応","不明","不明","Auth0 は restricted 名（カスタム追加不可）。他は記載なし。")
for c in ["name","given_name","family_name"]:
    e = "既定" if c=="name" else "既定（v1 のみ）"
    s(c,e,"設定で追加","設定で追加","設定で追加","既定（ID のみ）","Entra は profile スコープ必要（given/family は v2 で optional claim）。Keycloak は profile クライアントスコープのマッパー。Auth0 は scope 要求で ID トークン。Okta は profile スコープで ID トークン（AT と同時要求時は Org AS で name のみ等）。Cognito は属性があり読取権限がある場合 ID トークン。")
for c in ["middle_name","profile","picture","website","gender","birthdate","zoneinfo","updated_at"]:
    s(c,"不明","設定で追加","設定で追加","設定で追加","既定（ID のみ）","Entra の文書に該当クレームなし。Keycloak は profile スコープのマッパー（仕様のクレームに対応と記載）。Auth0 は OIDC 標準クレーム（non-restricted）。Okta は profile スコープ。Cognito は標準属性（値と読取権限がある場合）。")
s("nickname","既定（v1 のみ）","設定で追加","設定で追加","設定で追加","既定（ID のみ）","Entra は v1.0 basic claims に記載。他は profile スコープ / 属性。")
s("preferred_username","既定（v2 のみ）","設定で追加","設定で追加","設定で追加","既定（ID のみ）","Entra は v2 のみ（v1 は optional）で可変・認可不可。Okta は既定で Okta ユーザー名。Cognito は preferred_username 属性（alias 可）。")
s("locale","独自の名前で","設定で追加","設定で追加","設定で追加","既定（ID のみ）","Entra は xms_pl（LL-CC）/ xms_tpl（テナント）。")
s("email","設定で追加","設定で追加","設定で追加","設定で追加","既定（ID のみ）","Entra はゲストに既定、テナント内ユーザーは optional claim か v2 email スコープ、正しさ保証なし・認可不可。Okta は一意性に依存するなと明記。Cognito は属性があり読取可能なとき。")
s("email_verified","独自の名前で","設定で追加","設定で追加","設定で追加","既定（ID のみ）","Entra は email_verified を出さず xms_edov（ドメイン所有者検証、意味が違う）や verified_primary_email。Okta は primary email の検証。Cognito は管理者が直接 true にできる。")
s("phone_number","不明","設定で追加","設定で追加","設定で追加","既定（ID のみ）","Okta は E.164 と記載だが例示値は非 E.164。Cognito は + と数字のみ。")
s("phone_number_verified","不明","設定で追加","設定で追加","不明","既定（ID のみ）","Okta の scope-dependent claims 表に記載なし。Cognito は管理者が直接 true にできる。")
s("address","不明","設定で追加","設定で追加","設定で追加","既定（ID のみ）","Keycloak は address はオプションスコープの例で記載。")
s("act","独自の名前で","設定で追加","設定で追加","設定で追加","設定で追加","Entra は act を出さず Agent ID で azp/appid + xms_act_fct（+xms_par_app_azp）。Keycloak は delegation（26.8 preview）。Auth0 は OBO TE / Agent as Principal（5 レベル上限）。Okta は OBO TE（最大 5 アクター）。Cognito は token exchange で actor token 提示時のみ（2026-11-12〜）。いずれも AT のみ。")
s("may_act","不明","設定で追加","不明","不明","不可・未対応","Keycloak は delegation:user / delegation:client スコープで subject token に付与（preview）。Auth0 は restricted 名（発行の記載なし）。Cognito は発行も評価もしないと明記。")
s("cnf","不明","設定で追加","設定で追加","不明","不明","Keycloak は送信者制約（DPoP/mTLS）時、lightweight AT でも削除不可。Auth0 は mTLS バインディング（Case-specific）。")
s("authorization_details","不明","不明","設定で追加","不明","不明","Auth0 は RAR 利用時に AT に含まれる。")
for c in ["events","txn","sub_id","verified_claims"]:
    s(c,"不明","不明","不明","不明","不明","今回開いた 5 IdP の文書に発行の記載なし（Auth0 は events/txn を restricted 名として列挙）。" if c in("events","txn") else "今回開いた 5 IdP の文書に発行の記載なし。")
json.dump(S, open(sys.argv[1],"w",encoding="utf-8"), ensure_ascii=False, indent=1)
print(len(S))

# Brief for writing the per-case decisions of the claim catalogue

Inputs (read all before starting):
- E:\Github\jwt-claims-casestudy\catalog\DECISION_POLICY.md — the policy (Japanese). Follow it strictly.
- E:\Github\jwt-claims-casestudy\catalog\catalog.json — all rows with stable IDs (CLM-0001… and ORG-01…ORG-10).
- E:\Github\jwt-claims-casestudy\results\summary.md — the case-study experiment: element list and case IDs (G1…, A1…, B1…, C1…) to cite as 検証 ID.
- E:\Github\jwt-claims-casestudy\catalog\reviews\column-review-2026-11-17.md — the decision columns and allowed values.
- Guide (for 'ガイドの該当 Part'): E:\Github\jwt-claims-guide\research\outline.md (Parts 0–12).

Output: a JSON array written to the file named in your task, one object per row you were assigned:
```
{"id": "CLM-0123",
 "guide_part": "Part 4",              // the guide Part most relevant to this claim (string, may list two: "Part 3・10")
 "A": {"judgement": "...", "condition": "...", "alt": ["CLM-0001", "ORG-02"], "use_or_loss": "...", "revisit": "...", "checks": ["A3"]},
 "B": {...}, "C": {...}}
```
- judgement: exactly one of 必須（共通基準） / 採用 / 条件付き採用 / 不採用・代替あり / 不採用・不要 / 不採用・禁止 / 対象外
- condition: required for 条件付き採用 (when/where it is used, e.g. 「ID トークンのみ、ログイン画面の表示に」 or 「入口の正規化でのみ読む」), else "".
- alt: required (non-empty) for 不採用・代替あり — the IDs of the claims that cover it. Every alt ID must be judged 必須（共通基準）, 採用 or 条件付き採用 in the SAME case. Prefer ORG rows and the core standard rows (iss, sub, aud, exp, iat, jti, client_id, scope, act, authorization_details, groups/roles per RFC 9068). Look up their IDs in catalog.json (search by name and source).
- use_or_loss (Japanese, 1–2 sentences, required for every judgement except 対象外 where a short reason suffices): for adopted rows say WHEN/HOW it is used in this case; for rejected rows say WHAT BECOMES IMPOSSIBLE or what is lost (and, for 代替あり, how the alternative covers it). Be concrete to the case (A multi-tenant SaaS / B internal systems with SSO / C AI agents acting for users).
- revisit (Japanese): required for 条件付き採用 and all 不採用 judgements — the condition under which the decision should be reconsidered (e.g. 「トークンが取引先へ渡るようになったら」「RFC になったら」「IdP を Entra に一本化したら」).
- checks: case-study IDs from results/summary.md that test this decision, if any (else []).

Consistency rules:
- The core rows listed in the policy as 共通の基準 are 必須（共通基準） in all three cases. ORG rows follow the policy table (use in the listed cases; elsewhere 不採用・不要 with a reason).
- Vendor-specific rows (source_kind ベンダー独自): usually 不採用・代替あり with alt pointing at the ORG/standard claim the gateway maps them to, and condition-free; if the gateway must read them during normalisation, use 条件付き採用 with condition 「入口の正規化でのみ読む（内部トークンには載せない）」 and say what it maps to in use_or_loss.
- Personal data claims: never adopted in access tokens; at most 条件付き採用（ID トークンのみ…） in a case where the client needs it; otherwise 不採用・禁止 for access tokens or 不採用・不要.
- Drafts: at most 条件付き採用 with revisit 「RFC になったら」 etc.
- Unrelated domains (SIP/PASSporT, EAT device attestation, 3GPP, CI/CD workload attributes, eduPerson in a non-academic company…) → 対象外 with a one-line reason; but if a case could plausibly use it (e.g. CI/CD attributes for deploying the case-study services) explain why it is still out of scope.
- Write in plain Japanese. Do not invent facts about claims; rely on the row's own fields.

Validate your output before finishing (valid JSON; every assigned id present once; alt rules satisfied for IDs inside your own part; list any alt that points outside your part so the coordinator can cross-check).

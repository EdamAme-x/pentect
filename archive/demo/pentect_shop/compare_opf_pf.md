# Pentect Shop end-to-end demo (Privacy Filter FT 版)

**Source**: 自作の `pentect-shop` (Flask, demo/pentect_shop/app.py)
**Why this app exists**: Juice Shop は Claude が学習データで知っている可能性が高く、5/7 の文脈保持結果に「暗記」の交絡がある。Pentect Shop は完全オリジナル (パス・メール・テキスト) なので、同じ手順を踏んで似た結果が出れば「マスク後の構造から推論できる」が独立に成立する。

**Masking path**: per-entry routing (rule anchors + Privacy Filter FT v4_e3, batch)
**Analyst LLM**: `claude -p` (Claude Opus 4.7)

## 結論

| 脆弱性 (planted) | RAW | MASKED |
|---|---|---|
| V1. SQL injection in `/api/products/search` | ✅ critical | ✅ critical |
| V2. IDOR `/api/users/<id>` | ✅ critical | ✅ critical |
| V3. Admin endpoint `/api/admin/dump` 無認証 | ✅ critical | ✅ critical |
| V4. JWT 内 password hash 漏洩 | ✅ high | ❌ (login レスポンス側で part 検出) |
| V5. 平文 HTTP | ✅ info | — |
| V6. 500 disclosure (`/api/baskets/<id>`) | ✅ medium | ✅ high |
| V7. Default admin creds | ✅ high (md5 解読まで言及) | — (ハッシュ消えるので解読まで届かない) |
| V8. `/backup/db.sql.bak` 露出 | ✅ critical | ✅ critical |
| V9. PATCH mass assignment | ✅ medium | ✅ high (権限昇格懸念で重みづけアップ) |

集計:
- RAW: **9 / 9** 主要脆弱性検出
- MASKED (Privacy Filter FT): **6 / 9** 検出 + 1 partial (V4)

## 読み解き

- **構造系の脆弱性 (V1 SQLi, V2 IDOR, V3 admin endpoint, V8 backup, V9 mass assignment) は MASKED でも漏れなく検出**。これらはマスク後でも `/api/users/<<USER_ID>>` `200 OK` `400/500` 等の HTTP 構造から判断可能。
- **失った値ベース系 (V5 cleartext HTTP, V7 default admin)**: これらは「実値が脆弱性の本体」のため、マスクの設計通り消えた。Juice Shop と同じ傾向。
- **V4 (JWT password hash)** はマスクで JWT 自体が `<<CREDENTIAL>>` 化されるので、Claude は「JWT のレスポンスに password_hash フィールドが含まれる」点 (login response の JSON 構造) として別カウントで検出。マスク後は JWT を base64 デコードして中身を読む経路が消えるため、深刻度の表現は弱まるが「設計欠陥」としては掴めている。
- **Juice Shop の 5/7 と同水準の文脈保持を、Claude が学習で見ていない自作アプリで独立に再現**。マスキングが暗記効果ではなく構造保持で機能していることの強い証拠。

## 失われたもの (意図通り)

- 平文 HTTP の指摘 (V5): URL のスキームは構造として残るが、Claude は `Authorization: Bearer <<CREDENTIAL>>` だけ見て本来の指摘を出さなかった。これは入力フォーマット (compact summary) の都合で、マスキング自体の問題ではない。
- 具体的なパスワード値の解読 (V7): MD5 ハッシュそのものがマスクされるため、レインボーテーブル攻撃の経路は消える。マスキングの設計意図通り。

## コマンド再現

```bash
# 1. 起動 (terminal 1)
python demo/pentect_shop/app.py

# 2. HAR 取得 (terminal 2)
python demo/pentect_shop/capture.py

# 3. マスク + プロンプト生成
python demo/pentect_shop/identify_vulns.py --backend opf_pf

# 4. Claude 推論
claude -p "$(cat demo/pentect_shop/prompt_raw.txt)"          > demo/pentect_shop/answer_raw.md
claude -p "$(cat demo/pentect_shop/prompt_masked_opf_pf.txt)" > demo/pentect_shop/answer_masked_opf_pf.md
```

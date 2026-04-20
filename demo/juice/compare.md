# Pentect end-to-end demo: vulnerability identification

**Source**: `captured.har` (OWASP Juice Shop, Host rewritten to `juice-shop.local`)
**Masking path**: per-entry routing (rule anchors + FT Gemma 4B LoRA v2, batch)
**Analyst LLM**: `claude -p` (one-shot, Claude Code CLI)

23 interesting entries を 1 バッチで per-entry マスク、同じプレースホルダを使って RAW / MASKED の両方に同じプロンプトを投げ、特定された脆弱性を並べた。

## 結論

| 脆弱性 | RAW | MASKED | コメント |
|---|---|---|---|
| Admin endpoint 無認証アクセス | ✅ high | ✅ high | `/rest/admin/<<USER_ID>>` の 200 応答から両側 identify |
| IDOR (User enumeration) | ✅ high | ✅ high | 3 つの異なる USER_ID プレースホルダ + `role`/`createdAt` の並びから列挙パターン認識 |
| SQL injection in search | ✅ high | ✅ critical | SQLi payload (`'))--`) はマスクされず、masked 側はむしろ critical 判定 |
| /ftp/ directory exposure | ✅ medium | ✅ medium | `/ftp/` と `package.json.bak` の 403 が両側残る |
| 500 error info disclosure | ✅ medium | ✅ low | 両側とも検出、severity は軽め |
| HTTP 平文通信 | — | ✅ medium | masked 側のみ独自指摘 |
| JWT 内 password hash 混入 | ✅ critical | ❌ | **マスクで消失(意図通り — 外に出したくない情報)** |
| Default admin account | ✅ medium | ❌ | email local 部隠蔽で消失(意図通り) |
| Mass assignment via `fields` | ✅ low | — | RAW のみ |

## 読み解き

- **主要 high/critical 脆弱性は MASKED でも全て検出**(admin auth, IDOR, SQLi, ftp, 500 disclosure)
- **消えた critical (JWT 内 password hash / admin 実アドレス) は、そもそも外部 LLM に流したくない情報**
- per-entry ルーティングにより従来の `200 OK` → USER_ID 誤検知が消滅。`-> 200 OK` / `-> 401` / `-> 403` / `-> 500` の HTTP status がそのまま保持され、analyst の判断に必要な「応答コード」情報が完全に残る
- プレースホルダは URL 構造(`/api/Users/<<USER_ID>>`)や JSON フィールド境界を壊さず、同値性(同じ JWT → 同じ placeholder)もエントリ間で担保

## 設計メモ: なぜ per-entry か

- 単一の長文まとめでは FT Gemma の学習分布(単段落/1リクエスト)と形状が違い、0 spans 返す / 数値誤検知するなどの問題
- HAR の 1 entry = 1 請求という意味境界で分割 → 各 block が FT の in-distribution に近づく
- クロスエントリ一貫性は 2 段で担保:
  1. SHA ベースの placeholder(同じ値→同じ placeholder)
  2. HAR 全体への rule detector pass(グローバルアンカー)を各 block に注入

## コマンド再現

```bash
# 1. HAR 取得
cd demo/juice && docker compose up -d
python demo/juice/capture.py

# 2. summary + prompt 生成(FT v2、per-entry batch mask)
PENTECT_LLM_MAX_TOK=256 python demo/juice/identify_vulns.py

# 3. RAW と MASKED に対して claude -p
claude -p "$(cat demo/juice/prompt_raw.txt)"    > demo/juice/answer_raw.md
claude -p "$(cat demo/juice/prompt_masked.txt)" > demo/juice/answer_masked.md
```

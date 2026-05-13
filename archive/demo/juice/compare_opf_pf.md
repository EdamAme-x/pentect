# Pentect end-to-end demo: vulnerability identification (Privacy Filter FT 版)

**Source**: `captured.har` (OWASP Juice Shop, Host rewritten to `juice-shop.local`)
**Masking path**: per-entry routing (rule anchors + Privacy Filter FT v4_e3, batch)
**Analyst LLM**: `claude -p` (one-shot, Claude Code CLI, Claude Opus 4.7)

23 interesting entries を per-entry マスクし、生成された `prompt_masked_opf_pf.txt` を Claude に投げて特定された脆弱性を比較する。

## 結論

| 脆弱性 | RAW (Gemma 比較) | MASKED (Privacy Filter FT) | コメント |
|---|---|---|---|
| Admin endpoint 無認証アクセス | ✅ high | ❌ | PF 版マスクで `/rest/admin/<<USER_ID>>` 行に 200 OK 注釈が片方のみ残ったため Claude が「無認証」と読み取れず |
| IDOR (User enumeration) | ✅ high | ✅ high | 連番 USER_ID プレースホルダから両側 identify |
| SQL injection in search | ✅ critical | ✅ high | `'))--` ペイロードが URL エンコードのまま残り、両側で検出 |
| /ftp/ directory exposure | ✅ medium | ✅ medium | `/ftp/` と `package.json.bak` の 403 が残る |
| 500 error info disclosure | ✅ low | ✅ low | `-> 500 Internal Server Error` がそのまま保持 |
| HTTP 平文通信 | ✅ medium | ✅ high | URL の `http://` スキームが残るため検出可能 |
| JWT 内 password hash | ✅ critical | ❌ (意図通り消失) | CREDENTIAL マスクで JWT そのものが置換、payload 解析不可 |
| Default admin account | ✅ medium | ❌ (意図通り消失) | email local 部マスクで `admin@juice-sh.op` の `admin` が消失 |
| Mass assignment / `fields=` | — | ✅ low | PF 版のみ独自指摘 (`whoami?fields=id,email`) |
| Score Board exposure | — | ✅ low | PF 版のみ独自指摘 (`/api/Challenges/?name=Score%20Board`) |
| Excessive Data Exposure (`deluxeToken`, `lastLoginIp`) | — | ✅ medium | PF 版のみ独自指摘 |

## 読み解き

- **5 / 7 主要脆弱性を MASKED でも検出** (Gemma 4B FT 版と同水準)
- 失った 1 つ (Admin endpoint 無認証) は per-entry の splitting で 200 OK 行が片側のみに残ったため。Gemma 4B FT 版の `compare.md` では検出できていた → 検出器精度ではなく **マスク後の summary フォーマット** 由来の差
- 失った 2 つ (JWT password hash / Default admin) は CREDENTIAL / Email local 完全マスクの結果で **意図通り**
- PF 版は逆に `deluxeToken` / `Mass assignment` / `Score Board` の指摘が増えた = マスク後でも文脈が十分残っており、Claude が trace を読み込めている証拠

## 既知の課題 (面接で正直に話す)

Privacy Filter FT は HAR JSON の中に `"key":"value"` 形式のレスポンスが含まれると、`role`, `createdAt` などのキー名や、`admin`, `customer` などの enum 値を `INTERNAL_URL` 等に **過検出** することがある:

- 後処理フィルタで JSON キー位置の検出は破棄 (`engine/detectors/opf_pf.py`)
- 値側の誤検出 (`"role":"<<INTERNAL_URL>>"` など) は残る

これは学習データ (`training/data/opf/`) に JSON-shaped な例が無いことが原因 = 半年で追加 FT する範囲。今回の Juice Shop demo で見ても、誤検出されたフィールド ("role" の値など) は本来 PII ではないので Claude は無視でき、結論への影響は限定的だった。

## コマンド再現

```bash
# 1. マスク (PF FT 版)
python demo/juice/identify_vulns.py --backend opf_pf

# 2. Claude に投げる
claude -p "$(cat demo/juice/prompt_masked_opf_pf.txt)" > demo/juice/answer_masked_opf_pf.md

# 3. 結果は demo/juice/answer_masked_opf_pf.md にある
```

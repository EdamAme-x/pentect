# Pentect

Rule Based + fine-tuned Gemma 3 4B

## Image
```
# Input
GET http://jira.corp.internal/api/issues/1001
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMDAxIn0.sig

# Output
GET http://<<HOST_47a126fb>>/api/issues/<<ID_fe675fe7>>
Authorization: Bearer <<CREDENTIAL_8c6976e5>>
```

placeholder by hash

---

OWASP Juice Shop (demo) に 攻撃を行って HAR を取得し、マスクありとなしを Claude Opus 4.7 に推論させた結果

| 脆弱性 | RAW | MASKED |
|---|---|---|
| Public Admin endpoint | ✅ | ✅ |
| IDOR | ✅ | ✅ |
| SQL injection | ✅ | ✅ |
| Directory exposure | ✅ | ✅ |
| 500 info disclosure | ✅ | ✅ |
| JWT 内 password hash | ✅ | ❌ |
| Default admin account | ✅ | ❌ |

`demo/juice/compare.md`

ほとんどがマスク後でも残り、推論出来なかったのは値自体が脆弱性に繋がった物 (ここはマスキングにスコープを絞ると不可能だと考える)

---

| Engine | recall |
|---|---|
| Rule Based | 5.7% |
| Microsoft Presidio | 40.8% |
| Gemma 3 4B (vanilla) | 29.3% |
| **Gemma 3 4B + fine-tune** | **89.2%** |

(recall = 元のデータが見えてしまった割合)

テストケースは、学習データと被らないように調整した (過学習対策)

一つの長いデータをファインチューニングしたモデルに投げると破綻しやすいため、HAR のような分けられるデータは 1 entry 単位でバッチでマスキングする。

## 試したけど、駄目だった奴

- Qwen 2.5-3B を二段目の Verifier として置く案: 系統の異なるモデルで取りこぼしを救済する狙いだったが、救済 0 件に加えて誤検知 21 件で改善の余地ありありのあり

---

## Demo

```bash
pip install -e .

cd demo/juice && docker compose up -d
python demo/juice/capture.py
python demo/juice/identify_vulns.py

claude -p "$(cat demo/juice/prompt_raw.txt)"    > demo/juice/answer_raw.md
claude -p "$(cat demo/juice/prompt_masked.txt)" > demo/juice/answer_masked.md
```

```python
from engine.core import PentectEngine
result = PentectEngine(use_llm=True).mask_text(raw_text)
```

```bash
./scripts/dev.sh   # http://localhost:5173
```

## License

MIT

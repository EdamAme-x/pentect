# Pentect Shop

Original deliberately-vulnerable webapp. Used to verify Pentect's masking
pipeline on data Claude has not memorized (unlike OWASP Juice Shop).

## Run

```bash
# Terminal 1
python demo/pentect_shop/app.py    # listens on 127.0.0.1:5057

# Terminal 2
python demo/pentect_shop/capture.py
# wrote demo/pentect_shop/captured.har
```

## Planted vulnerabilities

| ID | Class | Endpoint |
|---|---|---|
| V1 | SQL injection | `GET /api/products/search?q=...` |
| V2 | IDOR | `GET /api/users/<id>` |
| V3 | Admin endpoint no-auth | `GET /api/admin/dump` |
| V4 | Sensitive data in JWT | `POST /api/login` |
| V5 | Cleartext HTTP | (server default) |
| V6 | Verbose 500 leak | `GET /api/baskets/<id>` |
| V7 | Default admin creds | `admin@pentect-shop.local / password` |
| V8 | Backup directory listing | `GET /backup/`, `/backup/db.sql.bak` |
| V9 | Mass assignment | `PATCH /api/users/<id>` |

## Why this exists

OWASP Juice Shop is widely indexed in LLM training data. A 5/7 score on
the masked Juice Shop trace could be explained by Claude recognizing the
project rather than reasoning over the masked structure. Pentect Shop
has unique paths, unique emails, and original phrasing, so a similar
result on this trace is harder to attribute to memorization.

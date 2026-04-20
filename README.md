# Pentect

ペネトレーションテスト中に取得した HAR (HTTP Archive) 等に含まれる機密を、LLM に安全に渡すためのマスキングエンジン。

```
# Input (Overview)
GET http://jira.corp.internal/api/issues/1001
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMDAxIn0.sig

# Output
GET http://<<INTERNAL_URL_HOST_47a126fb>>/api/issues/<<USER_ID_fe675fe7>>
Authorization: Bearer <<CREDENTIAL_xxxxxxxx>>
```

## Install

```bash
pip install -e .
```

### Python API

```python
from engine.core import PentectEngine

engine = PentectEngine()
result = engine.mask_har(har_text)
print(result.masked_text)
```

### Web UI (PoC)

```bash
./scripts/dev.sh
```

API (uvicorn) と UI (vite) を同時に起動するので、ブラウザで http://localhost:5173 を開けばOK。

## Tests

```bash
pytest tests/ -q
python -m eval.runner testcases/  
```

## Tasks

...

## License

MIT

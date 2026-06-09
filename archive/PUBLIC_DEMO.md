# Public demo

This demo is intentionally locked down for external exposure.

Default public settings:

- `PENTECT_ALLOWED_BACKENDS=opf_pf,presidio`
- `PENTECT_PF_DEVICE=cpu`
- `PENTECT_MAX_INPUT_CHARS=50000`
- `PENTECT_RATE_LIMIT_REQUESTS=30`
- `PENTECT_RATE_LIMIT_WINDOW_SECONDS=60`
- `PENTECT_ALLOW_RECOVERY=0`

Do not enable `gemma`, `hybrid`, or recovery maps on a public anonymous demo.

## Local production-like run

Build the UI once:

```bash
cd ui
pnpm install
pnpm build
cd ..
```

Run the API and static UI from one process:

```bash
set PENTECT_ALLOWED_BACKENDS=opf_pf,presidio
set PENTECT_PF_DEVICE=cpu
set PENTECT_MAX_INPUT_CHARS=50000
set PENTECT_RATE_LIMIT_REQUESTS=30
set PENTECT_RATE_LIMIT_WINDOW_SECONDS=60
set PENTECT_ALLOW_RECOVERY=0
python -m uvicorn server.main:app --host 127.0.0.1 --port 8000
```

Open:

```txt
http://127.0.0.1:8000/
```

## Docker

```bash
docker build -t pentect-demo .
docker run --rm -p 8000:8000 pentect-demo
```

For a hosted deployment, put a reverse proxy or platform-level limiter in front of this too. The in-app limiter is only a last-resort guard.

If the UI and API are served from different origins, set:

```bash
PENTECT_CORS_ORIGINS=https://your-demo.example
```

FROM node:22-bookworm-slim AS ui
WORKDIR /app/ui
RUN corepack enable
COPY ui/package.json ui/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY ui/ ./
RUN pnpm build

FROM python:3.13-slim AS app
WORKDIR /app

ENV PENTECT_ALLOWED_BACKENDS=opf_pf,presidio \
    PENTECT_PF_DEVICE=cpu \
    PENTECT_MAX_INPUT_CHARS=50000 \
    PENTECT_RATE_LIMIT_REQUESTS=30 \
    PENTECT_RATE_LIMIT_WINDOW_SECONDS=60 \
    PENTECT_ALLOW_RECOVERY=0 \
    PYTHONUNBUFFERED=1

COPY pyproject.toml README.md LICENSE ./
COPY engine ./engine
COPY server ./server
COPY training/runs/opf_pentect_v4_e3 ./training/runs/opf_pentect_v4_e3
RUN pip install --no-cache-dir .[baselines] \
    && pip install --no-cache-dir git+https://github.com/openai/privacy-filter.git

COPY --from=ui /app/ui/dist ./ui/dist

EXPOSE 8000
CMD ["python", "-m", "uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8000"]

#!/usr/bin/env bash
# Boot backend (uvicorn) and frontend (vite), then open the browser.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

API_PORT="${PENTECT_API_PORT:-8000}"
UI_PORT="${PENTECT_UI_PORT:-5173}"
UI_URL="http://localhost:${UI_PORT}"

pids=()
cleanup() {
  for pid in "${pids[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

echo "[pentect] starting API on :${API_PORT}"
uvicorn server.main:app --port "$API_PORT" --host 127.0.0.1 &
pids+=($!)

if [ ! -d "ui/node_modules" ]; then
  echo "[pentect] installing UI deps with pnpm"
  (cd ui && pnpm install)
fi

echo "[pentect] starting UI on :${UI_PORT}"
(cd ui && pnpm dev --port "$UI_PORT" --strictPort) &
pids+=($!)

# Wait for UI to respond before opening the browser.
for _ in $(seq 1 40); do
  if curl -sSf "$UI_URL" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

open_browser() {
  if command -v xdg-open >/dev/null 2>&1; then xdg-open "$1" >/dev/null 2>&1 || true
  elif command -v open >/dev/null 2>&1; then open "$1" >/dev/null 2>&1 || true
  elif command -v wslview >/dev/null 2>&1; then wslview "$1" >/dev/null 2>&1 || true
  elif command -v powershell.exe >/dev/null 2>&1; then powershell.exe /c start "$1" >/dev/null 2>&1 || true
  fi
}
echo "[pentect] opening $UI_URL"
open_browser "$UI_URL"

wait

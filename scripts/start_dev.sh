#!/usr/bin/env bash
# start_dev.sh — start the local dev environment (SQLite backend + Vite frontend)
#
# Usage:
#   bash scripts/start_dev.sh             # start both backend and frontend
#   bash scripts/start_dev.sh --backend   # backend only
#   bash scripts/start_dev.sh --frontend  # frontend only
#
# Environment variables (optional):
#   ASM_DB_PATH   path to SQLite file  (default: asm_notebook.sqlite3 in repo root)
#   BACKEND_PORT  uvicorn port          (default: 8000)
#   VITE_PORT     vite dev server port  (default: 5173)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

BACKEND_PORT="${BACKEND_PORT:-8000}"
VITE_PORT="${VITE_PORT:-5173}"
DB_PATH="${ASM_DB_PATH:-$REPO_ROOT/asm_notebook.sqlite3}"

MODE_BACKEND=true
MODE_FRONTEND=true
if [[ "${1:-}" == "--backend" ]];  then MODE_FRONTEND=false; fi
if [[ "${1:-}" == "--frontend" ]]; then MODE_BACKEND=false;  fi

PIDS=()
cleanup() {
  echo ""
  echo "==> Stopping dev servers..."
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

# ── Backend ──────────────────────────────────────────────────────────────────
if $MODE_BACKEND; then
  echo "==> Starting backend on http://localhost:$BACKEND_PORT"
  echo "    DB: $DB_PATH"
  ASM_DB_PATH="$DB_PATH" uvicorn asm_notebook.api_main:app \
    --host 0.0.0.0 \
    --port "$BACKEND_PORT" \
    --reload \
    --reload-dir asm_notebook \
    &
  PIDS+=($!)
fi

# ── Frontend ─────────────────────────────────────────────────────────────────
if $MODE_FRONTEND; then
  if [[ ! -d "$REPO_ROOT/frontend/node_modules" ]]; then
    echo "==> Installing frontend dependencies..."
    (cd "$REPO_ROOT/frontend" && npm install)
  fi
  echo "==> Starting frontend on http://localhost:$VITE_PORT"
  (cd "$REPO_ROOT/frontend" && \
    VITE_API_BASE="http://localhost:$BACKEND_PORT" \
    VITE_API_PREFIX="/api/v1" \
    npx vite --port "$VITE_PORT") &
  PIDS+=($!)
fi

echo ""
echo "==> Dev environment ready"
$MODE_BACKEND  && echo "    Backend:  http://localhost:$BACKEND_PORT/docs"
$MODE_FRONTEND && echo "    Frontend: http://localhost:$VITE_PORT"
echo ""
echo "    Press Ctrl+C to stop."
echo ""

wait

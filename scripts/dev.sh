#!/usr/bin/env sh
set -eu

PYTHON="${PYTHON:-python3}"
MASQE_INTERNAL_KEY="${MASQE_INTERNAL_KEY:-$("$PYTHON" -c 'import secrets; print(secrets.token_hex(32))')}"
export MASQE_INTERNAL_KEY
"$PYTHON" ai-guard/server.py &
AI_PID=$!
trap 'kill "$AI_PID" 2>/dev/null || true' EXIT INT TERM
go run ./cmd/masqe

#!/usr/bin/env sh
set -eu

PYTHON="${PYTHON:-python3}"
"$PYTHON" ai-guard/server.py &
AI_PID=$!
trap 'kill "$AI_PID" 2>/dev/null || true' EXIT INT TERM
go run ./cmd/masqe

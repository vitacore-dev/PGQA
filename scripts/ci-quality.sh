#!/usr/bin/env bash
# ruff (E,F) + black --check + pytest + basedpyright. Install: pip install -r requirements-dev.txt
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PATH="${ROOT}/.venv/bin:${PATH:-}"

PYTHON="${PYTHON:-python3}"
[[ -x "${ROOT}/.venv/bin/python" ]] && PYTHON="${ROOT}/.venv/bin/python"

SCOPES=(
  pg_query_analyzer/analysis
  pg_query_analyzer/storage
  pg_query_analyzer/db
  pg_query_analyzer/observed_plans
  pg_query_analyzer/ui
  pg_query_analyzer/visualization
  tests
  PSQLQA.py
)

ruff check --select E,F --ignore E501 "${SCOPES[@]}"
black --check --line-length 100 "${SCOPES[@]}"

"$PYTHON" -m pytest
basedpyright

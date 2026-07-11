#!/usr/bin/env bash
# Load .env into the current shell (run: source scripts/load-env.sh)
# Does not print secret values.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ENV_FILE:-$ROOT/.env}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "No $ENV_FILE — copy .env.example to .env and fill secrets." >&2
  return 1 2>/dev/null || exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

if [[ -z "${CURSOR_API_KEY:-}" ]]; then
  echo "CURSOR_API_KEY is empty after loading $ENV_FILE" >&2
  return 1 2>/dev/null || exit 1
fi

echo "Loaded env from $ENV_FILE (CURSOR_API_KEY is set)."

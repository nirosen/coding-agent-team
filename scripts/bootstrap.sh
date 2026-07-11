#!/usr/bin/env bash
# Bootstrap coding-agent-team on a VPN/SSH host (no secrets in git).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> coding-agent-team bootstrap"
echo "    root: $ROOT"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: missing required command: $1" >&2
    exit 1
  fi
}

need_cmd node
need_cmd npm

NODE_MAJOR="$(node -p "process.versions.node.split('.')[0]")"
if [[ "$NODE_MAJOR" -lt 22 ]]; then
  echo "ERROR: Node.js >= 22.13 required (found $(node -v))" >&2
  exit 1
fi
echo "==> node $(node -v)"

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "==> created .env from .env.example"
  echo "    Edit $ROOT/.env and set CURSOR_API_KEY (and optional Slack vars)."
  echo "    Then re-run: $ROOT/scripts/bootstrap.sh"
  echo "    Or: source $ROOT/scripts/load-env.sh && npm run team -- --cwd /path/to/repo --task \"...\""
  exit 0
fi

if ! grep -qE '^CURSOR_API_KEY=.+' .env || grep -qE '^CURSOR_API_KEY=(cursor_\.\.\.|)$' .env; then
  echo "ERROR: set a real CURSOR_API_KEY in $ROOT/.env" >&2
  exit 1
fi

echo "==> npm install"
npm install

# shellcheck disable=SC1091
source "$ROOT/scripts/load-env.sh"

echo "==> typecheck"
npm run typecheck

echo ""
echo "Bootstrap OK."
echo ""
echo "Run a team session (live in this terminal):"
echo "  source $ROOT/scripts/load-env.sh"
echo "  npm run team -- --cwd /path/to/your/repo --task \"Your task here\""
echo ""
echo "Examples:"
echo "  npm run team -- --cwd \"\$HOME/myrepo\" --fan-out --task \"Explain auth flow\""
echo "  npm run team -- --cwd \"\$HOME/myrepo\" --verbose --task \"Add rate limiting\""
echo ""

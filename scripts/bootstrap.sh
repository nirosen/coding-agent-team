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

ensure_path_local_bin() {
  export PATH="${HOME}/.local/bin:${PATH}"
}

install_cursor_cli() {
  ensure_path_local_bin
  if command -v agent >/dev/null 2>&1; then
    echo "==> Cursor CLI present: $(agent --version 2>/dev/null | head -1 || echo agent)"
    return 0
  fi

  need_cmd curl
  echo "==> installing Cursor CLI (curl https://cursor.com/install | bash)"
  curl https://cursor.com/install -fsS | bash
  ensure_path_local_bin

  if ! command -v agent >/dev/null 2>&1; then
    echo "ERROR: Cursor CLI install finished but 'agent' is not on PATH." >&2
    echo "       Add ~/.local/bin to PATH and re-run bootstrap." >&2
    exit 1
  fi
  echo "==> Cursor CLI installed: $(agent --version 2>/dev/null | head -1 || echo ok)"
}

cursor_cli_logged_in() {
  ensure_path_local_bin
  local out
  out="$(agent status 2>/dev/null || true)"
  [[ "$out" == *"Logged in"* ]]
}

login_cursor_cli() {
  ensure_path_local_bin
  need_cmd agent

  if cursor_cli_logged_in; then
    echo "==> Cursor CLI auth: $(agent status 2>/dev/null | head -1)"
    return 0
  fi

  # Headless / SSH: prefer API key (already required in .env for the SDK).
  if [[ -n "${CURSOR_API_KEY:-}" ]]; then
    echo "==> Cursor CLI: not browser-logged-in; CURSOR_API_KEY is set (SDK + agent --api-key / env)."
  fi

  if [[ ! -t 0 ]]; then
    echo "==> skipping interactive 'agent login' (no TTY)."
    echo "    For browser auth later: agent login"
    echo "    Or keep using CURSOR_API_KEY in .env (recommended on SSH)."
    return 0
  fi

  echo "==> Cursor CLI login (browser or device URL)"
  # On SSH without a local display, print the URL instead of opening a browser.
  if [[ -n "${SSH_CONNECTION:-}${SSH_TTY:-}" && -z "${DISPLAY:-}" && "$(uname -s)" != "Darwin" ]]; then
    export NO_OPEN_BROWSER=1
  fi
  # macOS-over-SSH often cannot use Keychain GUI; API key still covers the team SDK.
  if ! agent login; then
    echo "WARN: 'agent login' did not complete." >&2
    if [[ -n "${CURSOR_API_KEY:-}" ]]; then
      echo "      Continuing — CURSOR_API_KEY is set for coding-agent-team / agent." >&2
      return 0
    fi
    echo "ERROR: set CURSOR_API_KEY in .env or finish: agent login" >&2
    exit 1
  fi

  if cursor_cli_logged_in; then
    echo "==> Cursor CLI auth: $(agent status 2>/dev/null | head -1)"
  elif [[ -n "${CURSOR_API_KEY:-}" ]]; then
    echo "==> browser login unclear; CURSOR_API_KEY remains available for the team."
  else
    echo "ERROR: not logged in and CURSOR_API_KEY is empty" >&2
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

install_cursor_cli

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "==> created .env from .env.example"
  echo "    Edit $ROOT/.env and set CURSOR_API_KEY (and optional Slack vars)."
  echo "    Then re-run: $ROOT/scripts/bootstrap.sh"
  echo "    Or: source $ROOT/scripts/load-env.sh && npm run team -- --no-steer --cwd /path/to/repo --task \"...\""
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

login_cursor_cli

echo "==> typecheck"
npm run typecheck

echo ""
echo "Bootstrap OK."
echo ""
echo "Run a team session (live in this terminal):"
echo "  source $ROOT/scripts/load-env.sh"
echo "  npm run team -- --no-steer --cwd /path/to/your/repo --task \"Your task here\""
echo ""
echo "Examples:"
echo "  npm run team -- --no-steer --cwd \"\$HOME/myrepo\" --fan-out --task \"Explain auth flow\""
echo "  npm run team -- --no-steer --cwd \"\$HOME/myrepo\" --verbose --task \"Add rate limiting\""
echo ""

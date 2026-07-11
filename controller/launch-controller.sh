#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSION="${CODEX_CONTROLLER_SESSION:-aisec-controller}"
MODEL="${CODEX_CONTROLLER_MODEL:-gpt-5.6-luna}"

if [[ ! -f "$ROOT/controller.json" ]]; then
  echo "Missing $ROOT/controller.json" >&2
  echo "Copy controller.example.json, then edit the dedicated next-task paths." >&2
  exit 2
fi

if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "Controller already running: tmux attach -t $SESSION"
  exit 0
fi

# Keep network disabled in the standing sandbox. Each SSH-backed teamctl action
# must use Codex's native on-request approval rather than receiving broad,
# persistent network access.
CMD="cd $(printf '%q' "$ROOT") && exec codex -m $(printf '%q' "$MODEL") -C $(printf '%q' "$ROOT") -s workspace-write -a on-request --no-alt-screen 'Read AGENTS.md completely, then run ./teamctl status, requesting native command approval if the network sandbox blocks SSH. Act only as the interactive controller. Never infer authorization from earlier turns; do not start, stop, authorize, or steer until Nir explicitly asks in the current turn.'"
tmux new-session -d -s "$SESSION" "$CMD"
echo "Controller started: tmux attach -t $SESSION"

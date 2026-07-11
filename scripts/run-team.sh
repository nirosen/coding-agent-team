#!/usr/bin/env bash
# One-shot: clone (if needed) is done by you; this runs bootstrap then team.
# Usage:
#   ./scripts/run-team.sh --no-steer --cwd /path/to/repo --task "..."
# Extra flags are passed through to npm run team.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

"$ROOT/scripts/bootstrap.sh"

# shellcheck disable=SC1091
source "$ROOT/scripts/load-env.sh"

exec npm run team -- "$@"

#!/usr/bin/env bash
# Compatibility wrapper: all steering now goes through signed teamctl.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${AISEC_CONTROLLER_CONFIG:-$ROOT/controller/controller.json}"

if [[ $# -eq 0 ]]; then
  echo "Usage: $0 <guidance...>" >&2
  exit 2
fi

exec npm --prefix "$ROOT" run teamctl -- \
  --config "$CONFIG" steer "$@"

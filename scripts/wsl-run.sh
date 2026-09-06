#!/usr/bin/env bash
# Run a command inside the project directory under WSL2 with the ULPF toolchain on PATH.
# Usage: bash scripts/wsl-run.sh <command...>
set -euo pipefail
# shellcheck disable=SC1090
[ -f "$HOME/.ulpf-env" ] && source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/.."
exec "$@"

#!/usr/bin/env bash
# Run the learning-plane pytest suite (or the given test paths) inside the WSL venv.
set -uo pipefail
source "$HOME/.ulpf-env"
cd "$(dirname "$(readlink -f "$0")")/../learning"
export ULPF_ROOT="$(cd .. && pwd)"
python -m pytest -q "$@" 2>&1 | tail -${PYTEST_TAIL:-25}

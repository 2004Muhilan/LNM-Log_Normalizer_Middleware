#!/usr/bin/env bash
# Run one Go package's tests from Windows without shell-quoting trouble. Usage: go-test-pack.sh ./internal/pack/
set -uo pipefail
source "$HOME/.ulpf-env"
cd "$(dirname "$(readlink -f "$0")")/../runtime"
export ULPF_ROOT="$(cd .. && pwd)"
go test "${1:-./...}" 2>&1 | tail -${2:-15}

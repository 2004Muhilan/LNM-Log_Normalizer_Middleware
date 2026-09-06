#!/usr/bin/env bash
set -uo pipefail
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/../runtime"
gofmt -w ./internal
go test ./internal/dsl/ -run 'Replay|Synthetic|Golden' -v 2>&1 | grep -E "^(=== RUN|--- (PASS|FAIL|SKIP)|\s+replay_test|\s+golden_test|FAIL|ok)" | grep -vE "^=== RUN" | sed 's/^ *//' | head -60

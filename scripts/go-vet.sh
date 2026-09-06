#!/usr/bin/env bash
# gofmt + vet + build for the runtime module.
set -uo pipefail
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/../runtime"
gofmt -w ./internal ./cmd ./contracts
go mod tidy >/dev/null 2>&1
go vet ./... 2>&1 | head -60
go build ./... && echo "BUILD OK"

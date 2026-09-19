#!/usr/bin/env bash
# Build the runtime and run the Go suites P8 touches (lake, pipeline incl. renormalize, normalize, contracts), uncached.
set -uo pipefail
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/../runtime"
gofmt -l ./internal ./cmd ./contracts
go vet ./... || exit 1
go build -o bin/ulpf-runtime ./cmd/ulpf-runtime || exit 1
go test -count=1 ./internal/lake/ ./internal/pipeline/ ./internal/normalize/ ./contracts/ "$@" 2>&1 | grep -vE "no test files"
exit "${PIPESTATUS[0]}"

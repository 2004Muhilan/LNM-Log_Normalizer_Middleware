#!/usr/bin/env bash
# Build the runtime and run the Go suites touched by P6 (route DAG, pipeline, frame, pack, mlfeat).
set -uo pipefail
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/../runtime"
gofmt -l ./internal ./cmd ./contracts
go vet ./... || exit 1
go build -o bin/ulpf-runtime ./cmd/ulpf-runtime || exit 1
go test -count=1 ./internal/route/ ./internal/frame/ ./internal/pack/ ./internal/pipeline/ ./internal/normalize/ ./internal/dsl/ "$@" 2>&1 | grep -vE "no test files"

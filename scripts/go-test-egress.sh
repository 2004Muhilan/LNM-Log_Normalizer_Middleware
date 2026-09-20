#!/usr/bin/env bash
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/../runtime"
gofmt -w ./internal/egress ./internal/pipeline ./cmd
go vet ./internal/egress/ ./internal/pipeline/ ./cmd/... || exit 1
go test -count=1 ./internal/egress/ "$@" -v 2>&1 | grep -E "^(\s*--- |ok|FAIL|panic|\s+egress_test)" | cut -c1-300
exit "${PIPESTATUS[0]}"

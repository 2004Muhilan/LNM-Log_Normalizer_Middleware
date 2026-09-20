#!/usr/bin/env bash
# Run the corpus value-replay tests verbosely (oracle comparisons + digest pins).
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/../runtime"
gofmt -w ./internal/dsl/replay_values_test.go
go vet ./internal/dsl/ && go test -count=1 ./internal/dsl/ -run 'TestReplayValues' -v 2>&1 | grep -E "^(=== RUN|\s*--- |ok|FAIL|\s+replay_values_test)" | grep -v "=== RUN" | cut -c1-330

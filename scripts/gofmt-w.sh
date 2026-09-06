#!/usr/bin/env bash
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/../runtime" && gofmt -w ./internal ./cmd ./contracts && echo formatted

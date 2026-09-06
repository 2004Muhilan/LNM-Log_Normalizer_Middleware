#!/usr/bin/env bash
source "$HOME/.ulpf-env"
cd "$(dirname "$(readlink -f "$0")")/../runtime" && gofmt -w ./internal ./cmd ./contracts && echo formatted

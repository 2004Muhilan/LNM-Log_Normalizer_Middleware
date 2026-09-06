#!/usr/bin/env bash
# Run the P4 model path end to end against a live llama-server started from the shipped image:
# onboard (model proposes) -> certificates -> logformat -> promote -> verify-pack (Go, fail-closed).
# Usage: p4-model-smoke.sh [manifest id] [gguf file] [gpu|cpu]
set -uo pipefail
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/.."
id="${1:-granite-4.1-8b-q4_k_m}"; f="${2:-granite-4.1-8b-Q4_K_M.gguf}"; mode="${3:-gpu}"
gpu=(--gpus all); dev=()
[ "$mode" = cpu ] && { gpu=(); dev=(--device none); }
docker rm -f ulpf-p4-smoke >/dev/null 2>&1
docker run -d --name ulpf-p4-smoke "${gpu[@]}" -p 8080:8080 -v "$PWD/models/cache:/models:ro" ulpf-llama \
  -m "/models/$f" --parallel 1 --ctx-size 16384 --seed 0 -ngl auto "${dev[@]}" --jinja --no-warmup >/dev/null
for i in $(seq 1 120); do sleep 2; curl -sf http://127.0.0.1:8080/health >/dev/null && break; done
ULPF_MODEL_SERVER=http://127.0.0.1:8080 ULPF_MODEL_ID="$id" ULPF_MODE="${ULPF_MODE:-whole}" ULPF_BACKEND="$mode ngl=auto ($(hostname))" \
  bash scripts/p4-check.sh 2>&1 | sed -n '/model path/,$p'
docker rm -f ulpf-p4-smoke >/dev/null

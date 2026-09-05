#!/usr/bin/env bash
# P4 spike on THIS machine. Usage: bash scripts/p4-spike.sh <machine-label> [gpu|cpu] [extra spike.py args]
#   bash scripts/p4-spike.sh desktop-5060ti gpu
#   bash scripts/p4-spike.sh laptop-1650 gpu --ngl auto
#   bash scripts/p4-spike.sh laptop-1650 cpu --models qwen3.5-4b-q4_k_m
# Needs: Docker with the ulpf-llama image (scripts/build-llama-image.sh) and the weights in models/cache
# (scripts/fetch-models.sh). Results land in spike/results/<machine-label>/ and are committed.
set -uo pipefail
source "$HOME/.ulpf-env"
cd "$(dirname "$(readlink -f "$0")")/.."
export ULPF_ROOT="$PWD"
label="${1:?machine label}"; shift
mode="${1:-gpu}"; [ $# -gt 0 ] && shift
flag="--gpu"; [ "$mode" = "cpu" ] && flag="--cpu"
MODELS="${MODELS:-qwen3.5-9b-q4_k_m qwen3.5-4b-q4_k_m qwen3.5-4b-q8_0 qwen3.5-2b-q4_k_m granite-4.1-8b-q4_k_m gemma-4-12b-q4_0}"
python learning/tools/models.py verify $(for m in $MODELS; do echo --id "$m"; done) || exit 1
# shellcheck disable=SC2086
python learning/tools/spike.py run --machine "$label" $flag --models $MODELS --repeat "${REPEAT:-2}" --resume "$@"
python learning/tools/spike.py summarize

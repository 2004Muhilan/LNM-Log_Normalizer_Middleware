#!/usr/bin/env bash
# Start llama-server from the ulpf-llama image for one model and print the load/offload log lines.
# Usage: bash scripts/llama-logprobe.sh <gguf file name in models/cache> [ngl] [gpu|cpu]
set -uo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
f="${1:?gguf file}"; ngl="${2:-auto}"; mode="${3:-gpu}"
docker rm -f ulpf-logprobe >/dev/null 2>&1
gpu=(--gpus all); dev=()
[ "$mode" = cpu ] && { gpu=(); dev=(--device none); }
docker run -d --name ulpf-logprobe "${gpu[@]}" -v "$PWD/models/cache:/models:ro" ${IMAGE:-ulpf-llama} -m "/models/$f" --parallel 1 --ctx-size 8192 -ngl "$ngl" "${dev[@]}" --no-warmup ${LLAMA_EXTRA:-} >/dev/null
for i in $(seq 1 60); do
  sleep 2
  if docker logs ulpf-logprobe 2>&1 | grep -q "server is listening"; then break; fi
  [ "$(docker inspect -f '{{.State.Running}}' ulpf-logprobe)" = "true" ] || break
done
echo "running=$(docker inspect -f '{{.State.Running}}' ulpf-logprobe)"
docker logs ulpf-logprobe 2>&1 | grep -iE "offload|repeating layers|buffer size|using device|fit|error|CUDA0|CPU_Mapped|listening|n_gpu_layers|ggml_cuda_init|found [0-9]+ CUDA" | grep -vE "assigned to device" | head -60
docker rm -f ulpf-logprobe >/dev/null

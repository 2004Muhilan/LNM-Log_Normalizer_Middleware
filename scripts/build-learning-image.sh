#!/usr/bin/env bash
# Build the learning-plane image with ONE bundled, digest-verified model. Usage: build-learning-image.sh <manifest id>
# The weights come from a bind-mounted build context, never from the repository context (.dockerignore
# excludes models/cache as a second line of defence). The image verifies the digest again at start.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
id="${1:?manifest id, e.g. qwen3.5-4b-q4_k_m}"
export DOCKER_BUILDKIT=1
docker build -f learning/Dockerfile --target learning --build-arg MODEL="$id" --build-context models=models/cache -t "ulpf-learning:$id" . 2>&1 | tail -25
docker image inspect "ulpf-learning:$id" --format "ulpf-learning:$id {{.Size}} bytes"
echo "=== start check (digest verified at start, then llama-server; stopped after readiness)"
docker rm -f ulpf-learning-check >/dev/null 2>&1 || true
docker run -d --name ulpf-learning-check --network none -e ULPF_NGL=0 "ulpf-learning:$id" >/dev/null
for i in $(seq 1 90); do sleep 2; docker logs ulpf-learning-check 2>&1 | grep -qE "listening on http" && break; done
docker logs ulpf-learning-check 2>&1 | grep -E "model_hash|listening|MISMATCH|error" | head -5
docker rm -f ulpf-learning-check >/dev/null

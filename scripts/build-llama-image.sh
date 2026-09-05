#!/usr/bin/env bash
# Build the llama-server CUDA image (sm_75 + sm_120 in one binary, backends loaded at run time so the
# image also runs on a host with no CUDA driver). Long: compiles llama.cpp with CUDA (~75 min on the desktop).
# Usage: build-llama-image.sh [tag]   (default ulpf-llama)
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
tag="${1:-ulpf-llama}"
export DOCKER_BUILDKIT=1
docker build -f learning/Dockerfile --target llama -t "$tag" . 2>&1 | tail -40
docker image inspect "$tag" --format "$tag: {{.Size}} bytes"

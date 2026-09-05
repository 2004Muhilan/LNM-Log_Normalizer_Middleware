#!/usr/bin/env bash
# Build the llama-server CUDA image (sm_75 + sm_120 in one binary). Long: compiles llama.cpp with CUDA.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
export DOCKER_BUILDKIT=1
docker build -f learning/Dockerfile --target llama -t ulpf-llama . 2>&1 | tail -40
docker image inspect ulpf-llama --format 'ulpf-llama: {{.Size}} bytes' 

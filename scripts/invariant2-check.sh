#!/usr/bin/env bash
# Invariant 2 — the runtime carries no model and does no inference. Verified by BUILD INSPECTION:
#   (a) the Go binary's module graph (go version -m) contains no ML/inference dependency and its
#       strings contain no inference-engine or weights-format markers;
#   (b) the runtime container image's filesystem contains no weights, no inference library, no Python.
# Exit 1 on any hit. Run after scripts/p2-check.sh has built runtime/bin/ulpf-runtime and the image.
set -uo pipefail
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/.."
status=0
# Inspect the SHIPPED build (CGO_ENABLED=0, trimpath — what runtime/Dockerfile produces), not the dev binary.
BIN=$(mktemp -d)/ulpf-runtime
(cd runtime && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$BIN" ./cmd/ulpf-runtime) || { echo "build failed"; exit 1; }

echo "=== (a) Go binary: module graph"
go version -m "$BIN" | awk '$1=="dep"{print "  dep", $2, $3}'
if go version -m "$BIN" | awk '$1=="dep"{print $2}' | grep -Eiq 'llama|ggml|gguf|onnx|torch|tensorflow|openvino|tflite|whisper|transformers'; then
  echo "  FAIL: inference dependency in module graph"; status=1
else
  echo "  ok: no inference dependency (only the JSON Schema library and stdlib)"
fi
echo "=== (a) Go binary: strings"
hits=$(strings -n 6 "$BIN" | grep -Eic 'libllama|libggml|\.gguf|ggml_|llama_model|onnxruntime|torch::|cuda|cublas|safetensors' || true)
if [ "$hits" != "0" ]; then
  echo "  FAIL: $hits inference/weights markers in binary strings:"; strings -n 6 "$BIN" | grep -Ei 'libllama|libggml|\.gguf|ggml_|llama_model|onnxruntime|torch::|cuda|cublas|safetensors' | head -5; status=1
else
  echo "  ok: no inference-engine or weights-format strings"
fi
echo "=== (a) Go binary: static, no dynamic loader"
if file "$BIN" | grep -q "statically linked"; then echo "  ok: statically linked"; else echo "  FAIL: not static"; file "$BIN"; status=1; fi

if [ "${ULPF_SKIP_DOCKER:-0}" != "1" ]; then
  echo "=== (b) runtime image filesystem"
  docker image inspect ulpf-runtime >/dev/null 2>&1 || docker build -q -f runtime/Dockerfile --target runtime -t ulpf-runtime . >/dev/null
  cid=$(docker create ulpf-runtime)
  tmp=$(mktemp -d)
  docker export "$cid" | tar -tf - > "$tmp/files.txt"
  docker rm "$cid" >/dev/null
  n=$(wc -l < "$tmp/files.txt")
  echo "  files in image: $n"
  if grep -Eiq '\.gguf$|\.safetensors$|\.onnx$|\.pt$|\.bin$|libllama|libggml|libcuda|libcublas|libtorch|python3|site-packages|/venv/' "$tmp/files.txt"; then
    echo "  FAIL: weights/inference/python present:"; grep -Ei '\.gguf$|\.safetensors$|\.onnx$|\.pt$|\.bin$|libllama|libggml|libcuda|libcublas|libtorch|python3|site-packages|/venv/' "$tmp/files.txt" | head; status=1
  else
    echo "  ok: no weights, no inference library, no Python in the runtime image"
  fi
  echo "  image size: $(docker image inspect ulpf-runtime --format '{{.Size}}' | awk '{printf "%.1f MB", $1/1048576}')"
  rm -rf "$tmp"
fi
[ $status -eq 0 ] && echo "INVARIANT 2: PASS (by build inspection)" || echo "INVARIANT 2: FAIL"
exit $status

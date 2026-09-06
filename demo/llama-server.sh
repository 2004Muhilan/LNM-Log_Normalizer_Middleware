#!/usr/bin/env bash
# The model server for step 2: the 4B on the GPU, 20 layers offloaded, 8k context, weights from the ext4
# copy, the PTX compute cache kept in a named volume. Usage: llama-server.sh start|stop|status
source "$(dirname "$(readlink -f "$0")")/lib.sh"
case "${1:-status}" in
  start)
    if curl -s -m 2 "http://127.0.0.1:$LLAMA_PORT/health" 2>/dev/null | grep -q ok; then echo "llama-server already up on $LLAMA_PORT"; exit 0; fi
    [ -f "$DEMO_MODELS_DIR/$DEMO_MODEL_FILE" ] || { echo "weights missing: $DEMO_MODELS_DIR/$DEMO_MODEL_FILE (copy models/cache/$DEMO_MODEL_FILE there)"; exit 1; }
    docker rm -f "$LLAMA_NAME" >/dev/null 2>&1
    docker run -d --name "$LLAMA_NAME" --gpus all -p "$LLAMA_PORT:8080" -v "$DEMO_MODELS_DIR:/models:ro" -v ulpf-cuda-cache:/root/.nv/ComputeCache \
      "$LLAMA_IMAGE" -m "/models/$DEMO_MODEL_FILE" --parallel 1 --ctx-size "$LLAMA_CTX" --seed 0 --n-gpu-layers "$LLAMA_NGL" --jinja --no-warmup --verbose >/dev/null || exit 1
    for i in $(seq 1 90); do
      curl -s -m 2 "http://127.0.0.1:$LLAMA_PORT/health" 2>/dev/null | grep -q ok && { echo "llama-server up on $LLAMA_PORT: $(docker logs "$LLAMA_NAME" 2>&1 | grep -oE 'offloaded [0-9]+/[0-9]+ layers to GPU' | tail -1)"; exit 0; }
      docker inspect -f '{{.State.Running}}' "$LLAMA_NAME" 2>/dev/null | grep -q true || { echo "container exited:"; docker logs "$LLAMA_NAME" 2>&1 | tail -5; exit 1; }
      sleep 2
    done
    echo "llama-server did not become ready in 180 s"; docker logs "$LLAMA_NAME" 2>&1 | tail -5; exit 1 ;;
  stop) docker rm -f "$LLAMA_NAME" >/dev/null 2>&1; echo "llama-server stopped" ;;
  status)
    if curl -s -m 2 "http://127.0.0.1:$LLAMA_PORT/health" 2>/dev/null | grep -q ok; then
      echo "up on $LLAMA_PORT: $(docker logs "$LLAMA_NAME" 2>&1 | grep -oE 'offloaded [0-9]+/[0-9]+ layers to GPU' | tail -1)"
    else echo "down"; exit 1; fi ;;
esac

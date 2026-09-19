#!/usr/bin/env bash
# Shared by every demo script. Sourced, never run. Everything the demo writes lives under $ULPF_DEMO_STATE
# (default ~/ulpf-demo, on the WSL ext4 disk: fsync-fast, and the UI server reads it as /state/).
# The demo is assembly over P1–P7: no script here adds behaviour; each step calls the same CLIs the
# phase checks call and copies their artifacts into the state directory for the UI.
# shellcheck disable=SC2034
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
set -o pipefail   # every step sources this: without it `cmd | tee file || step_fail` tested tee, never cmd (P8 audit)
export DOCKER_CONFIG="${DOCKER_CONFIG:-/tmp/ulpf-dockercfg}"
[ -f "$DOCKER_CONFIG/config.json" ] || { mkdir -p "$DOCKER_CONFIG"; echo '{}' > "$DOCKER_CONFIG/config.json"; }
ROOT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
export ULPF_ROOT="$ROOT"
STATE="${ULPF_DEMO_STATE:-$HOME/ulpf-demo}"
RT="$ROOT/runtime/bin/ulpf-runtime"; CM="$ROOT/runtime/bin/ulpf-committer"; VF="$ROOT/runtime/bin/ulpf-verify"
GOLDEN="$ROOT/contracts/golden/squid-native"
SAMPLES="$GOLDEN/samples/access.log"
SAMPLES11="$ROOT/learning/fixtures/squid-native-11.log"
LOGFORMAT='logformat squid %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %[un %Sh/%<a %mt'
# the model on stage (Qwen3.5-4B-Q4: VRAM headroom, faster on Squid, three certificates); Granite is the
# recorded provider behind the pre-built vendor packs (scripts/p6-build-packs.sh)
DEMO_MODEL="${ULPF_DEMO_MODEL:-qwen3.5-4b-q4_k_m}"
DEMO_MODEL_FILE="${ULPF_DEMO_MODEL_FILE:-Qwen3.5-4B-Q4_K_M.gguf}"
DEMO_MODELS_DIR="${ULPF_DEMO_MODELS_DIR:-$HOME/ulpf-models}"
LLAMA_IMAGE="${ULPF_LLAMA_IMAGE:-ghcr.io/ggml-org/llama.cpp:server-cuda}"
LLAMA_PORT="${ULPF_LLAMA_PORT:-8081}"
LLAMA_NAME="ulpf-demo-llama"
# 20 layers on the GPU on EVERY machine: the offload split changes the 4B's labels, hence the certificates on
# stage (20 -> pos_1/pos_3/pos_5, the set the runbook narrates; 33/33 -> pos_1/pos_3/pos_4). Pre-flight pins it.
LLAMA_NGL="${ULPF_LLAMA_NGL:-20}"
DEMO_NGL_PINNED=20
LLAMA_CTX="${ULPF_LLAMA_CTX:-8192}"
# step 2's provider: model (live, the demo) | fixture (the P3 path: team-authored proposals; the one-flag
# fallback when the GPU path stalls — say so on stage)
DEMO_PROVIDER="${ULPF_DEMO_PROVIDER:-model}"
UI_PORT="${ULPF_UI_PORT:-8765}"
TCP_PORT="${ULPF_DEMO_TCP_PORT:-6514}"
STATUS="$STATE/status.json"

# the machine label recorded in provenance.proposal.backend: the GPU's name (or the hostname without one)
machine_label() {
  local g; g=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1)
  [ -n "$g" ] || g="cpu-$(hostname)"
  echo "$g" | tr '[:upper:]' '[:lower:]' | sed -E 's/nvidia |geforce //g; s/[^a-z0-9]+/-/g; s/^-|-$//g'
}
MACHINE_LABEL="${ULPF_MACHINE_LABEL:-$(machine_label)}"

learn() { (cd "$ROOT/learning" && python -m ulpf_learn "$@"); }

# status.json: {"run_id", "steps": {"1": {"title", "state", "started", "seconds", "note"}}, "current"}
status_write() { # step state [note] [seconds]
  python3 - "$STATUS" "$1" "$2" "${3:-}" "${4:-}" <<'EOF'
import json, sys, time, os
path, step, state, note, secs = sys.argv[1:6]
try:
    st = json.load(open(path))
except Exception:
    st = {"run_id": time.strftime("%Y-%m-%dT%H:%M:%S"), "steps": {}}
s = st["steps"].setdefault(step, {})
s["state"] = state
if state == "running":
    s["started"] = time.time()
    st["current"] = step
if note:
    s["note"] = note
if secs:
    s["seconds"] = float(secs)
st["updated"] = time.time()
tmp = path + ".tmp"
json.dump(st, open(tmp, "w"), indent=1)
os.replace(tmp, path)
EOF
}
step_begin() { # N title
  STEP_N="$1"; STEP_T0=$(date +%s.%N); mkdir -p "$STATE/step$1"
  python3 - "$STATUS" "$1" "$2" <<'EOF'
import json, sys, time, os
path, step, title = sys.argv[1:4]
try:
    st = json.load(open(path))
except Exception:
    st = {"run_id": time.strftime("%Y-%m-%dT%H:%M:%S"), "steps": {}}
st["steps"].setdefault(step, {})["title"] = title
tmp = path + ".tmp"; json.dump(st, open(tmp, "w"), indent=1); os.replace(tmp, path)
EOF
  status_write "$1" running
  echo; echo "================ step $1: $2 ================"
}
step_end() { # [note]
  local t1; t1=$(date +%s.%N)
  local secs; secs=$(python3 -c "import sys; print(round(float(sys.argv[2])-float(sys.argv[1]),1))" "$STEP_T0" "$t1")   # same clock at both ends
  status_write "$STEP_N" done "${1:-}" "$secs"
  echo "---- step $STEP_N done in ${secs}s"
}
step_fail() { status_write "$STEP_N" failed "${1:-failed}"; echo "---- step $STEP_N FAILED: ${1:-}"; exit 1; }
freeport_check() { python3 - "$1" <<'EOF'
import socket, sys
s = socket.socket(); s.settimeout(0.3)
sys.exit(0 if s.connect_ex(("127.0.0.1", int(sys.argv[1]))) != 0 else 1)
EOF
}

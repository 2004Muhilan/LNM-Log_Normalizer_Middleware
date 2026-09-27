#!/usr/bin/env bash
# Pre-flight: every external condition the six steps depend on, checked up front, loud, in the order
# they would otherwise bite mid-demo. Writes $STATE/preflight.json for the UI header. Exit 1 on any FAIL.
set -uo pipefail
source "$(dirname "$(readlink -f "$0")")/lib.sh"
cd "$ROOT"
fails=0; results=()
check() { # name command...
  local name="$1"; shift
  # bodies are `bash -c '...'`: a fresh shell without pipefail, where `cmd | tail -1` tests tail (P8 audit: five checks
  # could not fail). `bash -o pipefail -c` puts it back.
  [ "$1" = bash ] && [ "$2" = -c ] && { shift 2; set -- bash -o pipefail -c "$@"; }
  local out; out=$("$@" 2>&1); local rc=$?
  if [ $rc -eq 0 ]; then echo "  ok    $name  ${out:+— $out}"; results+=("{\"name\":$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$name"),\"ok\":true,\"detail\":$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1][:200]))' "$out")}")
  else echo "  FAIL  $name  — $out"; fails=$((fails+1)); results+=("{\"name\":$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$name"),\"ok\":false,\"detail\":$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1][:300]))' "$out")}"); fi
}
echo "=== pre-flight ($(date))"
check "toolchain (go, python venv)" bash -c 'go version >/dev/null && python -c "import jsonschema, re2, yaml, cryptography" && echo "$(go version | cut -d" " -f3), $(python --version)"'
check "working copy is byte-exact (no CRLF/mixed files vs LF blobs)" bash -c 'bad=$(git ls-files --eol | grep -E "w/(crlf|mixed)" | cut -f2); [ -z "$bad" ] && echo "git ls-files --eol: clean" || { echo "CRLF working copies (delete and git checkout -- each): $bad"; exit 1; }'
check "runtime binaries" bash -c "[ -x $RT ] && [ -x $CM ] && [ -x $VF ] && echo built"
check "evidence archive: required, its own slot beside the lake ($STATE/app/evidence-archive), committer key trusted" bash -c "[ -x $CM ] && [ -f keys/dev/ulpf-committer-dev.json ] && [ -f keys/trust/ulpf-committer-dev.pub.json ] && mkdir -p $STATE && d=\$(mktemp -d $STATE/.archive-probe.XXXX) && echo probe > \$d/x && sync \$d/x && rm -rf \$d && ! $RT run --pack $GOLDEN --input /dev/null --evidence \$(mktemp -d)/ev --out /dev/null 2>/dev/null && echo \"writable; the runtime refuses to start without --evidence-archive; the committer (always running) ships, keys/trust verifies its checkpoints; \$(df -h --output=avail $STATE | tail -1 | tr -d ' ') free\""
check "parser transparency log: log and witness keys trusted, the golden and vendor packs logged (the runtime refuses any other)" bash -c "[ -f keys/trust/ulpf-tlog-dev.vkey ] && [ -f keys/trust/ulpf-witness-dev.vkey ] && [ -x runtime/bin/ulpf-witness ] && runtime/bin/ulpf-tlog verify --pack $GOLDEN > /dev/null && for v in cisco-asa panos fortigate; do runtime/bin/ulpf-tlog verify --pack $STATE/p6/source-packs/\$v > /dev/null || exit 1; done && runtime/bin/ulpf-tlog list | tail -1"
check "dev keys and signed golden pack" bash -c "[ -f keys/dev/ulpf-pack-authority-dev.json ] && [ -f keys/trust/ulpf-pack-authority-dev.pub.json ] && $RT verify-pack --pack $GOLDEN | tail -1"
check "corpus cache" bash -c '[ -f corpus/cache/beats-cisco-asa/asa.log ] && [ -f corpus/cache/beats-panw-panos/traffic.log ] && [ -f corpus/cache/beats-fortinet-firewall/traffic.log ] && echo "asa, panos, fortigate fixtures present"'
check "state reset (vendor packs + mixed capture)" bash -c "[ -f $STATE/p6/source-packs/cisco-asa/pack.json ] && [ -f $STATE/p6/mixed.log ] && echo \"$(ls $STATE/p6/source-packs 2>/dev/null | tr '\n' ' ')\""
FSTYPE=$(df -T "$DEMO_MODELS_DIR" 2>/dev/null | awk 'NR==2{print $2}')
check "weights on ext4 ($DEMO_MODEL_FILE)" bash -c "[ -f $DEMO_MODELS_DIR/$DEMO_MODEL_FILE ] && echo '$FSTYPE' | grep -qE 'ext4|xfs|btrfs' && echo \"$(stat -c %s "$DEMO_MODELS_DIR/$DEMO_MODEL_FILE" 2>/dev/null) bytes on $FSTYPE\""
check "weights digest matches the manifest" bash -c "cd learning && python tools/models.py verify --id $DEMO_MODEL --cache $DEMO_MODELS_DIR | tail -1"
check "docker responsive" bash -c 'docker info --format "{{.ServerVersion}}" | sed "s/^/server /"'
check "gpu visible to docker" bash -c 'g=$(docker run --rm --gpus all nvidia/cuda:12.1.1-base-ubuntu22.04 nvidia-smi -L 2>/dev/null | head -1 || true); [ -n "$g" ] || g="(host only) $(nvidia-smi -L | head -1)"; echo "$g" | grep GPU'
check "offload split pinned at $DEMO_NGL_PINNED layers (the certificates on stage depend on it)" bash -c "if [ '$LLAMA_NGL' = '$DEMO_NGL_PINNED' ]; then echo 'ULPF_LLAMA_NGL=$LLAMA_NGL'; elif [ '${ULPF_DEMO_NGL_UNPINNED:-0}' = 1 ]; then echo 'UNPINNED by ULPF_DEMO_NGL_UNPINNED=1: ngl=$LLAMA_NGL — step 2 will NOT show the runbook certificate set'; else echo 'ULPF_LLAMA_NGL=$LLAMA_NGL, the demo is narrated against $DEMO_NGL_PINNED (measurement runs: ULPF_DEMO_NGL_UNPINNED=1)'; exit 1; fi"
check "llama-server on $LLAMA_PORT (ngl $LLAMA_NGL, ctx $LLAMA_CTX)" bash -c "curl -s -m 3 http://127.0.0.1:$LLAMA_PORT/health | grep -q ok && docker inspect $LLAMA_NAME --format '{{join .Args \" \"}}' | grep -q -- \"--n-gpu-layers $LLAMA_NGL\" && docker inspect $LLAMA_NAME --format '{{join .Args \" \"}}' | grep -q -- \"--ctx-size $LLAMA_CTX\" && docker logs $LLAMA_NAME 2>&1 | grep -oE 'offloaded [0-9]+/[0-9]+ layers to GPU' | tail -1"
check "llama-server answers a completion" bash -c "curl -s -m 60 http://127.0.0.1:$LLAMA_PORT/v1/chat/completions -H 'Content-Type: application/json' -d '{\"messages\":[{\"role\":\"user\",\"content\":\"Reply with the single word ok.\"}],\"max_tokens\":4,\"temperature\":0}' | python3 -c 'import json,sys; d=json.load(sys.stdin); c=d[\"choices\"][0]; n=d[\"usage\"][\"completion_tokens\"]; assert n > 0, \"no tokens generated\"; print(str(n)+\" tokens generated, finish=\"+str(c.get(\"finish_reason\")))'"
check "witness image (ulpf-verify)" bash -c 'docker image inspect ulpf-verify --format "{{.Size}}" | awk "{printf \"%.1f MB\", \$1/1048576}"'
check "tcp port $TCP_PORT free for the mixed stream" bash -c "$(declare -f freeport_check); freeport_check $TCP_PORT && echo free"
# air gap: every image and wheel the destinations need is local BEFORE the network goes (a pull on stage cannot happen offline)
OSV="${ULPF_OPENSEARCH_VERSION:-2.19.2}"
check "SIEM images local (OpenSearch + Dashboards $OSV)" bash -c "docker image inspect opensearchproject/opensearch:$OSV --format '{{.Size}}' > /dev/null && docker image inspect opensearchproject/opensearch-dashboards:$OSV --format '{{.Size}}' > /dev/null && echo 'both present, no pull needed'"
check "DuckDB in the venv (lake writer + lake page; no extension downloads used)" bash -c 'python -c "import duckdb; print(\"duckdb\", duckdb.__version__)"'
check "live-sequence ports free (${ULPF_LIVE_TCP_PORT:-6515} ${ULPF_LIVE_HTTP_PORT:-8516} ${ULPF_LIVE_SINK:-127.0.0.1:8790} ${ULPF_LIVE_LAKE:-127.0.0.1:8792}; the demo apps check their own)" bash -c "$(declare -f freeport_check); for p in ${ULPF_LIVE_TCP_PORT:-6515} ${ULPF_LIVE_HTTP_PORT:-8516} $(echo ${ULPF_LIVE_SINK:-127.0.0.1:8790} | cut -d: -f2) $(echo ${ULPF_LIVE_LAKE:-127.0.0.1:8792} | cut -d: -f2); do freeport_check \$p || { echo \"port \$p busy\"; exit 1; }; done; echo free"
check "memory headroom" bash -c 'a=$(free -m | awk "/Mem:/{print \$7}"); [ "$a" -gt 1500 ] && echo "${a} MB available in WSL"'
mkdir -p "$STATE"
python3 - "$STATE/preflight.json" "$fails" "${results[@]}" <<'EOF'
import json, sys, time
path, fails, *rows = sys.argv[1:]
json.dump({"at": time.time(), "fails": int(fails), "checks": [json.loads(r) for r in rows]}, open(path, "w"), indent=1)
EOF
if [ $fails -gt 0 ]; then echo "PRE-FLIGHT: $fails FAIL — do not start the demo"; exit 1; fi
echo "PRE-FLIGHT: all clear"

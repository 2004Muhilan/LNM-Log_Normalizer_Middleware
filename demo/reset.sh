#!/usr/bin/env bash
# One command back to the clean pre-demo state: stops the runtime and senders, wipes the state directory,
# rebuilds the binaries and dev keys, rebuilds the three vendor packs and the mixed capture from the corpus
# cache (recorded Granite proposals, scripts/p6-build-packs.sh), makes sure the witness image exists.
# Keeps the model server and the UI server running (both are stateless); `reset.sh --all` stops them too.
set -uo pipefail
source "$(dirname "$(readlink -f "$0")")/lib.sh"
cd "$ROOT"
t0=$(date +%s)
echo "=== reset: stopping runtime, senders, committer"
pkill -x ulpf-runtime 2>/dev/null; pkill -x ulpf-committer 2>/dev/null
[ -f "$STATE/sender.pid" ] && kill "$(cat "$STATE/sender.pid")" 2>/dev/null
pkill -f "demo/steps/5-sender" 2>/dev/null
# the live sequence's apps (demo/live): generator, consumer, the drift watch
pkill -f "demo/live/flowgen.py" 2>/dev/null; pkill -f "demo/live/sink.py" 2>/dev/null; pkill -f "tools/drift.py --watch" 2>/dev/null
docker rm -f ulpf-demo-witness >/dev/null 2>&1
if [ "${1:-}" = "--all" ]; then
  bash "$ROOT/demo/llama-server.sh" stop
  pkill -f "demo/serve-ui.py" 2>/dev/null && echo "ui server stopped"
fi
echo "=== reset: state directory $STATE"
chmod -R u+w "$STATE" 2>/dev/null; rm -rf "$STATE"; mkdir -p "$STATE"
echo "=== reset: binaries and dev keys"
bash scripts/keys-bootstrap.sh > /dev/null || { echo "keys/binaries FAILED"; exit 1; }
echo "=== reset: witness image"
docker image inspect ulpf-verify >/dev/null 2>&1 || DOCKER_BUILDKIT=1 docker build -q -f runtime/Dockerfile --target verify -t ulpf-verify . >/dev/null || { echo "ulpf-verify image FAILED"; exit 1; }
echo "=== reset: vendor packs and the mixed capture (recorded Granite proposals; ~1 min)"
[ -f corpus/cache/beats-cisco-asa/asa.log ] || { echo "corpus cache missing"; exit 1; }
ULPF_P6_WORK="$STATE/p6" bash scripts/p6-build-packs.sh > "$STATE/p6-build.log" 2>&1 || { echo "vendor pack build FAILED (see $STATE/p6-build.log)"; tail -5 "$STATE/p6-build.log"; exit 1; }
for p in cisco-asa panos fortigate; do "$RT" verify-pack --pack "$STATE/p6/source-packs/$p" | sed 's/^/  /' || exit 1; done
rm -rf "$STATE/p6/ev" "$STATE/p6/ev-asa"   # the P6 script's own runs; the demo's evidence is step 5's
python3 - "$STATUS" <<'EOF'
import json, sys, time
json.dump({"run_id": time.strftime("%Y-%m-%dT%H:%M:%S"), "reset_at": time.time(), "steps": {}}, open(sys.argv[1], "w"), indent=1)
EOF
echo "=== reset done in $(( $(date +%s) - t0 ))s: state clean, vendor packs built, mixed capture $(grep -c '' "$STATE/p6/mixed.log") lines"

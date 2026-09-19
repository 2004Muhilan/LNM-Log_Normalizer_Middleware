#!/usr/bin/env bash
# Capture one real run of the demo for the replay bundle: reset, pre-flight, then each step on its own
# with its terminal output saved, then the state directory copied. Output: ~/ulpf-demo-capture/
# (outside the repository — it contains Elastic-licensed fixture lines and is never committed).
set -uo pipefail
source "$(dirname "$(readlink -f "$0")")/../lib.sh"
cd "$ROOT"
CAP="${ULPF_DEMO_CAPTURE:-$HOME/ulpf-demo-capture}"
rm -rf "$CAP"; mkdir -p "$CAP/terminal"
bash demo/reset.sh > "$CAP/terminal/reset.txt" 2>&1 || { echo "reset failed"; exit 1; }
bash demo/preflight.sh > "$CAP/terminal/preflight.txt" 2>&1 || { echo "pre-flight failed"; cat "$CAP/terminal/preflight.txt"; exit 1; }
for n in 1 2 3 4 5 6; do
  script=$(ls "$ROOT/demo/steps/$n-"*.sh | head -1)
  bash "$script" > "$CAP/terminal/step$n.txt" 2>&1 || { echo "step $n failed"; tail -5 "$CAP/terminal/step$n.txt"; exit 1; }
  echo "captured step $n: $(tail -1 "$CAP/terminal/step$n.txt")"
done
# the state the UI reads, minus what the replay never needs (the P6 build's own outputs and logs)
rsync -a --exclude 'p6/ev*' --exclude 'p6/s-*' --exclude 'p6/*.txt' --exclude 'p6/packs' --exclude 'p6-build.log' --exclude '*/session' --exclude 'step3/session-fixture' "$STATE/" "$CAP/state/"
cp "$STATUS" "$CAP/status.json"
python3 - "$CAP/machine.json" "$MACHINE_LABEL" "$LLAMA_NGL" "$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1)" <<'EOF'
import json, sys
json.dump({"label": sys.argv[2], "ngl": sys.argv[3], "gpu": sys.argv[4] or None}, open(sys.argv[1], "w"), indent=1)
EOF
echo "capture: $(du -sh "$CAP" | cut -f1) in $CAP"

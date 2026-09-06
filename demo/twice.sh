#!/usr/bin/env bash
# The acceptance criterion: reset, run the whole sequence, reset, run it again — no manual repair between.
# Keeps both runs' status.json as $ULPF_DEMO_STATE/../ulpf-demo-run{1,2}.json and prints both timings.
set -uo pipefail
source "$(dirname "$(readlink -f "$0")")/lib.sh"
KEEP="$(dirname "$STATE")"
for i in 1 2; do
  echo "############## RUN $i: reset"
  bash "$ROOT/demo/reset.sh" || { echo "reset failed"; exit 1; }
  bash "$ROOT/demo/preflight.sh" || { echo "pre-flight failed"; exit 1; }
  echo "############## RUN $i: sequence"
  bash "$ROOT/demo/run.sh" || { echo "RUN $i FAILED"; cp "$STATUS" "$KEEP/ulpf-demo-run$i.json" 2>/dev/null; exit 1; }
  cp "$STATUS" "$KEEP/ulpf-demo-run$i.json"
done
echo "############## both runs complete"
python3 - "$KEEP/ulpf-demo-run1.json" "$KEEP/ulpf-demo-run2.json" <<'EOF'
import json, sys
a, b = (json.load(open(p)) for p in sys.argv[1:3])
print(f"{'step':6s} {'run 1':>8s} {'run 2':>8s}  title")
for k in sorted(a["steps"], key=int):
    print(f"{k:6s} {a['steps'][k].get('seconds', 0):8.1f} {b['steps'].get(k, {}).get('seconds', 0):8.1f}  {a['steps'][k].get('title', '')}")
print(f"{'total':6s} {sum(s.get('seconds', 0) for s in a['steps'].values()):8.1f} {sum(s.get('seconds', 0) for s in b['steps'].values()):8.1f}")
EOF

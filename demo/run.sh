#!/usr/bin/env bash
# The demo sequence, one runnable order. Usage: run.sh [first-step] [last-step]   (default 1 6)
#   demo/run.sh        # all six steps
#   demo/run.sh 2 2    # re-run step 2 only (e.g. re-onboarding after drift, by hand — the same path)
# Every step is its own script under demo/steps/ and runs standalone, in the TERMINAL (the six-step page was removed on the laptop
# branch; the demo with pages is demo/start-demo.sh). Steps write under $ULPF_DEMO_STATE; timings land in status.json and are printed at the end.
set -uo pipefail
source "$(dirname "$(readlink -f "$0")")/lib.sh"
first="${1:-1}"; last="${2:-6}"
T0=$(date +%s)
for n in $(seq "$first" "$last"); do
  script=$(ls "$ROOT/demo/steps/$n-"*.sh 2>/dev/null | head -1)
  [ -n "$script" ] || { echo "no step $n"; exit 1; }
  bash "$script" || { echo; echo "STEP $n FAILED — see docs/demo-runbook.md 'when something hangs'"; exit 1; }
done
echo
echo "================ timings (run $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["run_id"])' "$STATUS")) ================"
python3 - "$STATUS" <<'EOF'
import json, sys
st = json.load(open(sys.argv[1]))
tot = 0.0
for k in sorted(st["steps"], key=int):
    s = st["steps"][k]; tot += s.get("seconds", 0) or 0
    print(f"  step {k}  {s.get('seconds', 0):7.1f}s  {s.get('state'):8s}  {s.get('title', '')}  — {s.get('note', '')[:90]}")
print(f"  total   {tot:7.1f}s")
EOF
echo "wall: $(( $(date +%s) - T0 ))s"

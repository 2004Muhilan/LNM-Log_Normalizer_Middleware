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
  python3 - "$STATE" > "$KEEP/ulpf-demo-run$i.facts.json" <<'EOF'
import json, sys
S = sys.argv[1]
s2 = json.load(open(f"{S}/step2/session-before.json")); st = json.load(open(f"{S}/step5/stats.json")); s6 = json.load(open(f"{S}/step6/result.json"))
s4 = json.load(open(f"{S}/step4/result.json"))
print(json.dumps({"step2_certificates": sorted((k, c["evidence"]["discriminator"].get("ambiguity_class")) for k, c in s2["certificates"].items()),
                  "step2_request": (s2.get("pending_request") or {}).get("discriminator_id"),
                  "step4": {k: s4[k] for k in ("propagated_slots", "operator_responses", "promoted", "pending_request_resolves")},
                  "step5": {k: st[k] for k in ("frames", "emitted", "quarantined", "drift_signals", "ml_records", "emitted_by_family", "quarantine_reasons", "candidate_set_sizes", "gap_kinds")},
                  "step6_leaf": (s6.get("tampered_leaf") or "").split(" (")[0]}, sort_keys=True, indent=1))
EOF
done
echo "############## both runs complete"
if cmp -s "$KEEP/ulpf-demo-run1.facts.json" "$KEEP/ulpf-demo-run2.facts.json"; then echo "run 1 and run 2 SHOWED the same thing (certificates, request, propagation, stream counts by family, tampered leaf)"
else echo "RUNS DIFFER in what they showed:"; diff "$KEEP/ulpf-demo-run1.facts.json" "$KEEP/ulpf-demo-run2.facts.json"; exit 1; fi
python3 - "$KEEP/ulpf-demo-run1.json" "$KEEP/ulpf-demo-run2.json" <<'EOF'
import json, sys
a, b = (json.load(open(p)) for p in sys.argv[1:3])
print(f"{'step':6s} {'run 1':>8s} {'run 2':>8s}  title")
for k in sorted(a["steps"], key=int):
    print(f"{k:6s} {a['steps'][k].get('seconds', 0):8.1f} {b['steps'].get(k, {}).get('seconds', 0):8.1f}  {a['steps'][k].get('title', '')}")
print(f"{'total':6s} {sum(s.get('seconds', 0) for s in a['steps'].values()):8.1f} {sum(s.get('seconds', 0) for s in b['steps'].values()):8.1f}")
EOF

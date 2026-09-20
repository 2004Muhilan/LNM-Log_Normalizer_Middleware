#!/usr/bin/env bash
# The live sequence's acceptance criterion: run it twice, no manual repair between, and both runs must SHOW the same
# thing. What is compared is what does not depend on the wall clock: the event class, that the two certificates the
# demo is built around fired (endpoint_orientation on both addresses, temporal_role on the timestamp), the assertions,
# what propagated, the two signatures the monitor fired on, the families in the database, and that the accounting
# balanced (generated == evidence records == database rows). Counts are NOT compared: the generator runs on a clock.
# The model's other certificates are NOT compared either: its labels on the unasserted columns vary with the sample
# lines, which carry real timestamps (they are printed for both runs).
# Needs what the six steps need: demo/reset.sh once, and the model server for the live provider.
set -uo pipefail
source "$(dirname "$(readlink -f "$0")")/../lib.sh"
KEEP="$(dirname "$STATE")"
[ -f "$STATUS" ] || bash "$ROOT/demo/reset.sh" || { echo "reset failed"; exit 1; }
for i in 1 2; do
  echo "############## LIVE RUN $i"
  t0=$(date +%s)
  bash "$ROOT/demo/live/run-live.sh" > "$KEEP/ulpf-live-run$i.log" 2>&1 || { echo "LIVE RUN $i FAILED"; grep -aE "FAILED|^---- " "$KEEP/ulpf-live-run$i.log" | tail -5; exit 1; }
  grep -aE "^---- live" "$KEEP/ulpf-live-run$i.log" | cut -c1-200
  echo "wall: $(( $(date +%s) - t0 ))s"
  python3 - "$STATE/live" > "$KEEP/ulpf-live-run$i.facts.json" 2> "$KEEP/ulpf-live-run$i.varies.txt" <<'EOF'
import json, sys
L = sys.argv[1]
s1, s2 = (json.load(open(f"{L}/session-v{k}.before.json")) for k in (1, 2))
a1, a2 = (json.load(open(f"{L}/session-v{k}/session.json")) for k in (1, 2))
w = json.load(open(f"{L}/watch.json")); sm = json.load(open(f"{L}/summary.json"))
cls = lambda s, k: (s["certificates"].get(f"cert_flowtap-01_pos{k}") or {}).get("evidence", {}).get("discriminator", {}).get("ambiguity_class")
print(json.dumps({"event_class": s1["proposal"]["event_class_uid"], "built_around": {f"pos_{k}": cls(s1, k) for k in (1, 4, 6)}, "blockers_before": len(s1["verdict"]["blockers"]),
                  "assertions_v1": [r["fields"][0] for r in a1["resolutions"]], "propagated_v2": sorted(h["slot_index"] + 1 for h in s2["propagated"]), "assertions_v2": [r["fields"][0] for r in a2["resolutions"]],
                  "monitor": [(e["state"], e["message"].split("unknown_signatures: ")[-1].split(" (")[0] if e["state"] == "fired" else "") for e in w["events"]],
                  "families": sorted(sm["by_family"]), "balanced": sm["ok"] and sm["generated"] == sm["frames"] == sm["rows"]}, sort_keys=True, indent=1))
print("certificates v1:", sorted((k.split("_")[-1], cls(s1, k.split("pos")[-1]) or c["status"]) for k, c in s1["certificates"].items()), "| v2:", sorted(k.split("_")[-1] for k in s2["certificates"]), "| counts:", {k: sm[k] for k in ("generated", "usable", "quarantined", "backfilled", "rows")}, file=sys.stderr)
EOF
  cat "$KEEP/ulpf-live-run$i.varies.txt"
done
echo "############## both live runs complete"
if cmp -s "$KEEP/ulpf-live-run1.facts.json" "$KEEP/ulpf-live-run2.facts.json"; then echo "live run 1 and live run 2 SHOWED the same thing"; cat "$KEEP/ulpf-live-run1.facts.json"
else echo "LIVE RUNS DIFFER in what they showed:"; diff "$KEEP/ulpf-live-run1.facts.json" "$KEEP/ulpf-live-run2.facts.json"; exit 1; fi

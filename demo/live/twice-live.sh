#!/usr/bin/env bash
# The live sequence's acceptance criterion: run it twice, no manual repair between, and both runs must SHOW the same
# thing. What is compared is what does not depend on the wall clock: the Tier 1 decision (and that nothing was parsed before
# it), the event class, the certificates the demo is built around, the request and the number of evidence requests, the
# assertions, typed values, the ALERT (binding, what propagated, what was promoted, what was withheld, the pack version), the
# signatures the monitor fired on, the evidence-log records for the outage and the pack changes, and that the accounting
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
s1 = json.load(open(f"{L}/session-v1.before.json")); a1 = json.load(open(f"{L}/session-v1/session.json")); a2 = json.load(open(f"{L}/autoheal/session/session.json"))
al = json.load(open(f"{L}/autoheal/alert-latest.json")); t1 = json.load(open(f"{L}/tier1-decision.json"))
w = json.load(open(f"{L}/watch.json")); sm = json.load(open(f"{L}/summary.json"))
ev = json.loads(open(f"{L}/run-1/out.jsonl").readline())
cls = lambda s, k: (s["certificates"].get(f"cert_flowtap-01_pos{k}") or {}).get("evidence", {}).get("discriminator", {}).get("ambiguity_class")
k = sm["evidence_record_kinds"]
print(json.dumps({"tier1": {"decision": t1["decision"], "operator": t1["operator_id"], "parsed_before_the_decision": t1["usable_when_decided"]},
                  "event_class": s1["proposal"]["event_class_uid"], "built_around": {f"pos_{n}": cls(s1, n) for n in (1, 4, 6)}, "blockers_before": len(s1["verdict"]["blockers"]),
                  "request": s1["pending_request"]["discriminator_id"], "evidence_requests_v1": a1["metrics"]["evidence_requests"], "assertions_v1": [r["fields"][0] for r in a1["resolutions"]],
                  "typed": {"time_is_int_ms": isinstance(ev["time"], int), "event_time_set": ev["_lineage"]["event_time"] == ev["time"], "vendor": ev["metadata"]["product"]["vendor_name"]},
                  "alert": {"bound": al["source_binding"]["bound"], "propagated": sorted(x["slot"] for x in al["propagated"]), "auto_promoted": sorted(m["attribute"] for m in al["auto_promoted"]),
                            "withheld": sorted(x["slot"] for x in al["withheld"]), "pack_version": al["pack"]["pack_version"], "operator": a2["operator_id"]},
                  "assertions_after_the_alert": [r["fields"][0] for r in a2["resolutions"]],
                  "monitor": [(e["state"], e["message"].split("unknown_signatures: ")[-1].split(" (")[0] if e["state"] == "fired" else "") for e in w["events"]],
                  "evidence_records": {"pack_activated": k.get("pack_activated"), "egress_outage_recorded": k.get("egress_stalled", 0) >= 1 and k.get("egress_resumed", 0) >= 1},
                  "families": sorted(sm["by_family"]), "balanced": sm["ok"] and sm["generated"] == sm["frames"] == sm["rows"]}, sort_keys=True, indent=1))
print("certificates v1:", sorted((c.split("_")[-1], cls(s1, c.split("pos")[-1]) or v["status"]) for c, v in s1["certificates"].items()), "| model proposed for the withheld columns:", [(x["slot"], x["proposed"]) for x in al["withheld"]],
      "| counts:", {n: sm[n] for n in ("generated", "usable", "quarantined", "backfilled", "rows")}, file=sys.stderr)
EOF
  cat "$KEEP/ulpf-live-run$i.varies.txt"
done
echo "############## both live runs complete"
if cmp -s "$KEEP/ulpf-live-run1.facts.json" "$KEEP/ulpf-live-run2.facts.json"; then echo "live run 1 and live run 2 SHOWED the same thing"; cat "$KEEP/ulpf-live-run1.facts.json"
else echo "LIVE RUNS DIFFER in what they showed:"; diff "$KEEP/ulpf-live-run1.facts.json" "$KEEP/ulpf-live-run2.facts.json"; exit 1; fi

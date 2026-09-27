#!/usr/bin/env bash
# Step 8 (P8; optional, after the six: `bash demo/run.sh 8 8`) — drift healing, the demonstrable path.
# Healing is SEMI-automatic by design (architecture §3.6): re-learning from untrusted input on its own is
# an attack surface, so the machine detects and a human re-onboards. The story, all of it from what is
# already on disk after step 5:
#   1. the drift monitor reads step 5's quarantine: a message id INSIDE the declared ASA domain that no
#      onboarded family owns (302015) is a RE-ONBOARD CANDIDATE; the two values OUTSIDE their domains are
#      DOMAIN VIOLATIONS and are never candidates;
#   2. the quarantined event's raw bytes come back out of the evidence store (raw_hash checked) — they were
#      retained when nothing could read them; the operator adds the device's capture of that message id;
#   3. the operator re-onboards THROUGH THE SAME PATH the audience watched in step 2: a spec, the model's
#      labels, certificates, one evidence request, the vendor's field-order documentation, promotion, a signed
#      pack. 302015 is a new L3 anchor value, so under the §4.4 key propagation cannot pre-empt it;
#   4. the same capture is replayed before and after, each run in its own evidence store: quarantined
#      drops 3 -> 2, the 302015 line now flows through its own family, and the two genuine domain
#      violations stay quarantined — which is the point.
# Touches nothing steps 5–7 own (its evidence and outputs live under step8/).
source "$(dirname "$(readlink -f "$0")")/../lib.sh"
cd "$ROOT"
step_begin 8 "Drift healing (detect, re-onboard, replay)"
D="$STATE/step8"; chmod -R u+w "$D" 2>/dev/null; rm -rf "$D" "$STATE/packs/asa-302015" "$STATE/source-packs/cisco-asa-healed"; mkdir -p "$D"
[ -f "$STATE/step5/q.jsonl" ] && [ -f "$STATE/step5/stats.json" ] || step_fail "step 5 has not run"
KEY="asa-message-id=302015"; FAM="asa-302015"

echo "--- 1. drift monitor over step 5's quarantine (detection only)"
(cd learning && python tools/drift.py --quarantine "$STATE/step5/q.jsonl" --stats "$STATE/step5/stats.json" --json "$D/drift.json") | tee "$D/drift.txt" || step_fail "drift monitor"
python3 - "$D/drift.json" "$KEY" <<'EOF' || step_fail "the monitor did not report what step 5 quarantined"
import json, sys
s = json.load(open(sys.argv[1])); key = sys.argv[2]
cands = {r["key"]: r["events"] for r in s["reonboard_candidates"]}; viol = {r["key"] for r in s["domain_violations"]}
ok = cands == {key: 1} and viol == {"asa-message-id=999999", "panos-log-type=WEIRD"} and not s["parse_success_drop"] and not s["unknown_signatures"]
sys.exit(0 if ok else 1)
EOF

echo "--- 2. samples: the quarantined bytes back out of the evidence store, plus the device's capture of that message id"
(cd learning && python tools/drift.py --quarantine "$STATE/step5/q.jsonl" --stats "$STATE/step5/stats.json" --evidence "$STATE/ev" --extract "$KEY" --out "$D/from-evidence.log") || step_fail "extract from evidence"
grep -h '%ASA-6-302015:' corpus/cache/beats-cisco-asa/asa.log > "$D/from-device.log" || step_fail "no 302015 lines in the corpus cache"
cat "$D/from-evidence.log" "$D/from-device.log" | awk '!seen[$0]++' > "$D/samples.log"
echo "samples: $(grep -c '' "$D/from-evidence.log") from the evidence store + $(grep -c '' "$D/from-device.log") from the device capture = $(grep -c '' "$D/samples.log") distinct lines"

echo "--- 3. re-onboard through the same path as step 2 (provider: $DEMO_PROVIDER)"
S="$D/session"
args=(--samples "$D/samples.log" --spec "$ROOT/drafts/sufficiency/asa-302015.json" --source-id asa-fw-01 --operator op-014 --session "$S" --vendor cisco-asa --family-id "$FAM" --unwrap-envelope)
if [ "$DEMO_PROVIDER" = "model" ]; then
  curl -s -m 3 "http://127.0.0.1:$LLAMA_PORT/health" | grep -q ok || step_fail "llama-server not up on $LLAMA_PORT (fallback: ULPF_DEMO_PROVIDER=fixture)"
  args+=(--provider model --model-id "$DEMO_MODEL" --server "http://127.0.0.1:$LLAMA_PORT" --mode whole --backend "cuda ngl=$LLAMA_NGL $MACHINE_LABEL")
else
  # the fallback replays the model's recorded labels for the SIBLING family 302013 (same field names, same guide section):
  # say so on stage — the model never saw 302015 on this path
  echo "FALLBACK: recorded proposals of the sibling family asa-302013 (the model did not label 302015 on this path)"
  args+=(--provider recorded --recording "$ROOT/spike/results/desktop-5060ti/granite-4.1-8b-q4_k_m__gpu__asa-302013__whole.json")
fi
learn onboard-spec "${args[@]}" | tee "$D/onboard.txt" || step_fail "onboard-spec"
cp "$S/session.json" "$D/session-before.json"
learn certificates --session "$S" | tee "$D/certificates.txt"
python3 - "$D/session-before.json" <<'EOF' || step_fail "healing must go through a real evidence request: propagation must not have pre-empted it"
import json, sys
s = json.load(open(sys.argv[1]))
ok = s["state"] == "awaiting_evidence" and s.get("pending_request") and not s.get("propagated") and len(s["certificates"]) >= 1
print(f"state {s['state']}; certificates {len(s['certificates'])}; propagated slots {len(s.get('propagated') or [])}; request: {(s.get('pending_request') or {}).get('discriminator_id')}")
sys.exit(0 if ok else 1)
EOF
learn respond --session "$S" --discriminator vendor_schema_field_order --input "Cisco Secure Firewall ASA Series Syslog Messages: 302015 Built {inbound|outbound} UDP connection" | tee "$D/respond.txt" || step_fail "respond"
learn promote --session "$S" --out "$STATE/packs/$FAM" --pack-id "$FAM" --produced-by auto-healed | tee "$D/promote.txt" || step_fail "promote"
learn merge "$STATE"/p6/packs/asa-{302013,302014,106023,305011} "$STATE/packs/$FAM" --out "$STATE/source-packs/cisco-asa-healed" --pack-id cisco-asa-fw-01 --vendor cisco-asa --pack-version 1.1 | tee "$D/merge.txt" || step_fail "merge"
"$RT" verify-pack --pack "$STATE/source-packs/cisco-asa-healed" | tee -a "$D/merge.txt" || step_fail "verify healed pack"

echo "--- 4. replay the same capture before and after (own evidence stores; steps 5-7 untouched)"
CAP="$STATE/p6/mixed.log"
replay() { # name asa-pack
  "$RT" run --dev-no-evidence-archive --pack "$2" --pack "$STATE/p6/source-packs/panos" --pack "$STATE/p6/source-packs/fortigate" --pack "$STATE/source-packs/squid" \
     --source-id mixed-relay-01 --input "$CAP" --evidence "$D/ev-$1" --out "$D/out-$1.jsonl" --quarantine "$D/q-$1.jsonl" 2> "$D/runtime-$1.err" || { cat "$D/runtime-$1.err"; return 1; }
  grep -E '^\{' "$D/runtime-$1.err" | tail -1 > "$D/stats-$1.json"
}
replay before "$STATE/p6/source-packs/cisco-asa" || step_fail "replay before"
replay after "$STATE/source-packs/cisco-asa-healed" || step_fail "replay after"
python3 - "$D" "$FAM" <<'EOF' | tee "$D/summary.txt"
import json, sys
d, fam = sys.argv[1:3]
b, a = (json.load(open(f"{d}/stats-{k}.json")) for k in ("before", "after"))
qa = [json.loads(l) for l in open(f"{d}/q-after.jsonl")]
healed = a["emitted_by_family"].get(f"cisco-asa-fw-01/{fam}", 0)
print(f"before: frames {b['frames']}  emitted {b['emitted']}  quarantined {b['quarantined']}  {json.dumps(b['quarantine_reasons'])}")
print(f"after : frames {a['frames']}  emitted {a['emitted']}  quarantined {a['quarantined']}  {json.dumps(a['quarantine_reasons'])}   cisco-asa-fw-01/{fam}: {healed}")
for r in qa:
    print(f"  still quarantined [{r['stage']}] {r['reason'][:100]}")
others_same = all(b["emitted_by_family"].get(k) == v for k, v in a["emitted_by_family"].items() if not k.endswith("/" + fam))
ok = (b["frames"] == a["frames"] and b["quarantined"] == 3 and a["quarantined"] == 2 and a["emitted"] == b["emitted"] + 1 and healed == 1 and others_same
      and a["quarantine_reasons"] == {"routing_drift": 2} and len(qa) == 2 and all(r["stage"] == "routing_drift" for r in qa))
json.dump({"before": b, "after": a, "healed_family": fam, "healed_events": healed, "ok": ok}, open(f"{d}/result.json", "w"), indent=1)
sys.exit(0 if ok else 1)
EOF
[ ${PIPESTATUS[0]} -eq 0 ] || step_fail "healing did not move the quarantine count 3 -> 2 (see step8/summary.txt)"
step_end "302015 detected as a re-onboard candidate, onboarded through the usual path, quarantined 3 -> 2; two domain violations still quarantined"

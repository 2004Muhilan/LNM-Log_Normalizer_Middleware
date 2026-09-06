#!/usr/bin/env bash
# Step 4 — propagation: an 11-slot Squid family from the same source; the ten slots step 2 resolved are
# resolved here under the §4.4 key with NO request; the family promotes with zero operator responses; the
# only certificate left concerns the new 11th slot and is retained. Then the two families are merged into
# one signed source pack. The proposal here is the fixture (P3 path): propagation is about resolutions,
# not the model — say so.
source "$(dirname "$(readlink -f "$0")")/../lib.sh"
cd "$ROOT"
step_begin 4 "Propagation (11-slot Squid, zero responses)"
[ -f "$STATE/propagation.json" ] || step_fail "no propagation store: step 2 has not run"
S="$STATE/step4/session"; rm -rf "$S" "$STATE/packs/squid-11" "$STATE/source-packs/squid"
learn onboard --provider fixture --samples "$SAMPLES11" --source-id squid-proxy-01 --operator op-014 --session "$S" --propagation-store "$STATE/propagation.json" | tee "$STATE/step4/onboard.txt" || step_fail "onboard"
cp "$S/session.json" "$STATE/step4/session.json"
learn promote --session "$S" --out "$STATE/packs/squid-11" --pack-id squid-native-11 | tee "$STATE/step4/promote.txt" || step_fail "promote"
python3 - "$STATE/step4/session.json" "$STATE/step4/result.json" "$STATE/step4/promote.txt" <<'EOF' || step_fail "propagation check"
import json, sys
s = json.load(open(sys.argv[1]))
prop = sorted({h["slot_index"] for h in s.get("propagated", [])})
m = {}
for line in open(sys.argv[3]):
    if line.startswith("metrics:"):
        m = json.loads(line.split(":", 1)[1])
req = s.get("pending_request") or {}
res = {"propagated_slots": prop, "evidence_requests": m["evidence_requests"], "operator_responses": m["operator_responses"], "promoted": m["promoted"],
       "pending_request_resolves": req.get("resolves"), "blockers": s["verdict"]["blockers"]}
json.dump(res, open(sys.argv[2], "w"), indent=1)
print(json.dumps(res))
ok = prop == list(range(10)) and m["operator_responses"] == 0 and m["promoted"]
sys.exit(0 if ok else 1)
EOF
mkdir -p "$STATE/source-packs"
learn merge "$STATE/packs/squid-10" "$STATE/packs/squid-11" --out "$STATE/source-packs/squid" --pack-id squid-proxy-01 | tee "$STATE/step4/merge.txt" || step_fail "merge"
"$RT" verify-pack --pack "$STATE/source-packs/squid" | tee -a "$STATE/step4/merge.txt" || step_fail "verify merged pack"
step_end "10 slots propagated, 0 operator responses, promoted; source pack merged and verified"

#!/usr/bin/env bash
# Step 2 — live onboarding of Squid: six unseen lines -> structure induced -> the 4B on the GPU labels the
# slots -> certificates -> one logformat request -> the operator's answer -> promoted -> signed pack
# verified by the Go runtime. ULPF_DEMO_PROVIDER=fixture is the one-flag fallback (P3 path).
source "$(dirname "$(readlink -f "$0")")/../lib.sh"
cd "$ROOT"
step_begin 2 "Live onboarding (Squid, $DEMO_PROVIDER)"
S="$STATE/step2/session"; rm -rf "$S" "$STATE/packs/squid-10"
mkdir -p "$STATE/packs"
args=(--samples "$SAMPLES" --source-id squid-proxy-01 --operator op-014 --session "$S" --propagation-store "$STATE/propagation.json")
if [ "$DEMO_PROVIDER" = "model" ]; then
  curl -s -m 3 "http://127.0.0.1:$LLAMA_PORT/health" | grep -q ok || step_fail "llama-server not up on $LLAMA_PORT (fallback: ULPF_DEMO_PROVIDER=fixture)"
  args+=(--provider model --model-id "$DEMO_MODEL" --server "http://127.0.0.1:$LLAMA_PORT" --mode whole --backend "cuda ngl=$LLAMA_NGL laptop-1650")
else
  args+=(--provider fixture)
fi
echo "provider: $DEMO_PROVIDER"
t0=$(date +%s.%N)
learn onboard "${args[@]}" | tee "$STATE/step2/onboard.txt" || step_fail "onboard"
t1=$(date +%s.%N)
cp "$S/session.json" "$STATE/step2/session-before.json"
learn certificates --session "$S" | tee "$STATE/step2/certificates.txt"
echo; echo "operator answer: $LOGFORMAT"
learn respond --session "$S" --discriminator device_logformat_configuration --input "$LOGFORMAT" | tee "$STATE/step2/respond.txt" || step_fail "respond"
cp "$S/session.json" "$STATE/step2/session-after.json"
learn promote --session "$S" --out "$STATE/packs/squid-10" --pack-id squid-native-live | tee "$STATE/step2/promote.txt" || step_fail "promote"
"$RT" verify-pack --pack "$STATE/packs/squid-10" | tee "$STATE/step2/verify.txt" || step_fail "verify-pack"
python3 - "$STATE/step2" "$DEMO_PROVIDER" "$LOGFORMAT" "$t0" "$t1" <<'EOF'
import json, sys, time
d, provider, logformat, t0, t1 = sys.argv[1:6]
pack = json.load(open(f"{d}/../packs/squid-10/pack.json"))
after = json.load(open(f"{d}/session-after.json"))
metrics = None
for line in open(f"{d}/promote.txt"):
    if line.startswith("metrics:"):
        metrics = json.loads(line.split(":", 1)[1])
json.dump({"provider": provider, "model_id": (after.get("proposal_provenance") or {}).get("model_id"),
           "model_hash": pack["provenance"].get("model_hash"), "proposal_seconds": round(float(t1) - float(t0), 1),
           "logformat": logformat, "verify": open(f"{d}/verify.txt").read().strip(), "metrics": metrics,
           "pack_id": pack["pack_id"], "signed_by": pack["signing"]["authority_id"]}, open(f"{d}/result.json", "w"), indent=1)
EOF
step_end "$(tail -1 "$STATE/step2/verify.txt")"

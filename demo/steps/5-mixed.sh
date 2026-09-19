#!/usr/bin/env bash
# Step 5 — the mixed live stream: four packs (three vendor packs pre-built from recorded Granite
# proposals, the Squid source pack promoted live in steps 2 and 4) in one runtime, syslog over TCP with
# RFC 6587 framing, every byte to the evidence store first, the decision DAG routing each frame to its
# family or quarantining it (the three adversarial lines: two drift signals, one unowned family), the ML
# feature tuple per event, and peer B falling silent — the silence gap record appended as a leaf while
# peer A is still streaming.
source "$(dirname "$(readlink -f "$0")")/../lib.sh"
cd "$ROOT"
step_begin 5 "Mixed stream: four packs, one runtime"
for p in "$STATE/p6/source-packs/cisco-asa" "$STATE/p6/source-packs/panos" "$STATE/p6/source-packs/fortigate" "$STATE/source-packs/squid"; do
  [ -f "$p/pack.json" ] || step_fail "missing pack $p (steps 2–4, reset)"
done
freeport_check "$TCP_PORT" || step_fail "port $TCP_PORT busy (pkill -x ulpf-runtime)"
CAP="$STATE/p6/mixed.log"; N=$(grep -c '' "$CAP"); TOTAL=$((N + 3))
LAKE="$STATE/lake"; chmod -R u+w "$LAKE" 2>/dev/null; rm -rf "$LAKE"   # a fresh run is a fresh lake: versions are never rewritten in place
EV="$STATE/ev"; rm -rf "$EV" "$STATE/step5"/*.jsonl "$STATE/step5/stats.json" "$STATE/step5/progress.json" "$STATE/step5/gaps.json"
RATE="${ULPF_DEMO_RATE:-12}"
"$RT" run --pack "$STATE/p6/source-packs/cisco-asa" --pack "$STATE/p6/source-packs/panos" --pack "$STATE/p6/source-packs/fortigate" --pack "$STATE/source-packs/squid" \
   --source-id mixed-relay-01 --listen "tcp:127.0.0.1:$TCP_PORT" --max-frames "$TOTAL" --silence-after 4s --idle-timeout 20s \
   --evidence "$EV" --lake "$LAKE" --out "$STATE/step5/out.jsonl" --quarantine "$STATE/step5/q.jsonl" --ml-out "$STATE/step5/ml.jsonl" 2> "$STATE/step5/runtime.err" &
RTPID=$!
sleep 0.7
kill -0 $RTPID 2>/dev/null || { cat "$STATE/step5/runtime.err"; step_fail "runtime did not start"; }
# gap records as they appear (uncommitted for now: the committer runs in step 6)
( while kill -0 $RTPID 2>/dev/null; do "$VF" gaps --evidence "$EV" --trust keys/trust --json 2>/dev/null > "$STATE/step5/gaps.json.tmp" && mv "$STATE/step5/gaps.json.tmp" "$STATE/step5/gaps.json"; sleep 1; done ) &
GAPPID=$!
python3 "$ROOT/demo/steps/5-sender.py" "$TCP_PORT" "$CAP" "$STATE/step5/progress.json" "$RATE" &
echo $! > "$STATE/sender.pid"
echo "streaming $N lines from peer A at $RATE/s after 3 lines from peer B (which then goes silent)..."
wait $RTPID; rc=$?
wait "$(cat "$STATE/sender.pid")" 2>/dev/null; rm -f "$STATE/sender.pid"
kill $GAPPID 2>/dev/null; wait $GAPPID 2>/dev/null
"$VF" gaps --evidence "$EV" --trust keys/trust --json > "$STATE/step5/gaps.json" 2>/dev/null
[ $rc -eq 0 ] || { cat "$STATE/step5/runtime.err"; step_fail "runtime exited $rc"; }
grep -E '^\{' "$STATE/step5/runtime.err" | tail -1 > "$STATE/step5/stats.json"
python3 - "$STATE/step5/stats.json" <<'EOF' | tee "$STATE/step5/summary.txt"
import json, sys
st = json.load(open(sys.argv[1]))
print(f"frames {st['frames']}  emitted {st['emitted']}  quarantined {st['quarantined']}  drift signals {st['drift_signals']}  ml records {st['ml_records']}  gap records {st['gap_records']} {st['gap_kinds']}  peers {st['peers']}")
print("by family:", json.dumps(st["emitted_by_family"]))
print("quarantine reasons:", json.dumps(st["quarantine_reasons"]), " candidate-set sizes:", json.dumps(st["candidate_set_sizes"]))
# expected VALUES, not only a balanced sum: the capture is fixed (98 lines + 3 from peer B), three lines are adversarial.
# (The balanced-sum check alone passed a run with 92 emitted / 9 quarantined — CRLF fixture, 2026-09-20.)
expect_q = {"routing": 1, "routing_drift": 2}
ok = (st["frames"] == st["emitted"] + st["quarantined"] and st["quarantined"] == 3 and st["quarantine_reasons"] == expect_q
      and st["ml_records"] == st["emitted"] and st["gap_kinds"].get("silence", 0) >= 1 and st["drift_signals"] == 2
      and st["emitted_by_family"].get("squid-proxy-01/positional-11") == 6 and st["emitted_by_family"].get("squid-proxy-01/positional-10") == 6)
if not ok:
    print("UNEXPECTED: wanted quarantined 3", expect_q, "and both Squid families at 6")
sys.exit(0 if ok else 1)
EOF
[ ${PIPESTATUS[0]} -eq 0 ] || step_fail "stream did not behave (see step5/summary.txt)"
"$VF" gaps --evidence "$EV" --trust keys/trust | tee "$STATE/step5/gaps.txt"
step_end "$(head -1 "$STATE/step5/summary.txt")"

#!/usr/bin/env bash
# The OTHER drift signal, live: `parse_success_drop` — events ROUTED to a family and then REFUSED by its parser.
# For a positional family that needs a change the router does not see and the parser does: whitespace. The generator's
# `drift-pad` adds one trailing space to every line (format v3). Needs a promoted flowtap pack: run demo/live/run-live.sh
# first. ~12 s. Not part of the narrated sequence; it exists so that the claim "this signal can fire on a live stream"
# is a measurement. It also shows the limit: this drift cannot be healed by re-onboarding — induction tokenises on
# whitespace exactly like the router, so the induced spec rejects the very samples it was induced from.
source "$(dirname "$(readlink -f "$0")")/../lib.sh"
cd "$ROOT"
LIVE="$STATE/live"; D="$LIVE/parse-drop"; PORT="${ULPF_LIVE_TCP_PORT:-6515}"
[ -f "$LIVE/packs/flowtap-v1/pack.json" ] || { echo "no promoted flowtap pack: run demo/live/run-live.sh first"; exit 1; }
pkill -f "demo/live/[f]lowgen.py .*$D/" 2>/dev/null; chmod -R u+w "$D" 2>/dev/null; rm -rf "$D"; mkdir -p "$D/run-1"
"$RT" run --dev-no-evidence-archive --pack "$GOLDEN" --pack "$LIVE/packs/flowtap-v1" --source-id live-ingress-01 --listen "tcp:127.0.0.1:$PORT" --idle-timeout 60s \
   --evidence "$D/ev" --out "$D/run-1/out.jsonl" --quarantine "$D/run-1/q.jsonl" 2> "$D/runtime.err" & RTPID=$!
(cd learning && exec python tools/drift.py --watch "$D/run-1" --json "$D/watch.json" --window 40 --threshold 0.8 --min-frames 20 --interval 0.5 --stop-file "$D/watch.stop") > "$D/watch.log" 2>&1 & WPID=$!
sleep 0.8; echo run > "$D/gen.control"
python3 demo/live/flowgen.py --to "127.0.0.1:$PORT" --rate 20 --status "$D/generator.json" --control "$D/gen.control" & GPID=$!
ok=1
for _ in $(seq 1 100); do python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))["usable_total"] >= 40 else 1)' "$D/watch.json" 2>/dev/null && break; sleep 0.2; done
echo drift-pad > "$D/gen.control"
for _ in $(seq 1 100); do python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))["fired"] else 1)' "$D/watch.json" 2>/dev/null && { ok=0; break; }; sleep 0.2; done
sleep 1; echo stop > "$D/gen.control"; wait $GPID 2>/dev/null; kill -TERM $RTPID; wait $RTPID 2>/dev/null; touch "$D/watch.stop"; wait $WPID 2>/dev/null
grep -a FIRED "$D/watch.log" | tail -1
python3 - "$D/watch.json" <<'EOF' || ok=1
import json, sys
w = json.load(open(sys.argv[1]))
good = w["dominant_signal"] == "parse_success_drop" and w["signals"]["parse_success_drop"] and not w["signals"]["unknown_signatures"]
print(f"dominant signal: {w['dominant_signal']}; routed-then-refused events in the window: {sum(r['events'] for r in w['signals']['parse_success_drop'])}; unknown signatures: {len(w['signals']['unknown_signatures'])}")
sys.exit(0 if good else 1)
EOF
# the limit: the padded lines cannot be onboarded — the induced spec rejects its own samples
python3 demo/live/flowgen.py --sample 12 --format 3 > "$D/padded.log"
(learn onboard --provider fixture --fixture "$ROOT/demo/live/flowtap-proposals.json" --samples "$D/padded.log" --source-id flowtap-pad --operator op-014 --session "$D/session" --vendor none 2>&1 | grep -E "blocker|fail to parse" | head -2) || true
echo "parse-drop-check: $([ $ok -eq 0 ] && echo PASS || echo FAIL)"
exit $ok

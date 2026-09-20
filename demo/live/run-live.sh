#!/usr/bin/env bash
# The LIVE sequence (parallel to the six rehearsed steps; touches nothing they own — everything is under $STATE/live):
#
#   flowgen (a generator app)  --syslog/TCP-->  ULPF runtime  --HTTP POST-->  sink (a consumer app, SQLite)
#
#   A  an unknown source appears: the runtime (which only knows Squid) quarantines every line — bytes retained,
#      nothing guessed — and the drift monitor reports an unknown signature;
#   B  LIVE ONBOARDING from the evidence log: the quarantined bytes come back out of the evidence store (raw_hash
#      checked), the model labels them, the ambiguity certificates fire, the operator resolves the mandatory ones by
#      OPERATOR ASSERTION (there is no vendor document for a format we invented), a signed pack is promoted;
#   C  the pack is loaded (runtime restart, generator paused around it): events flow to the consumer's database;
#   D  DRIFT: the generator changes its format mid-run; parse success collapses, the monitor FIRES, the stream
#      quarantines (bytes retained again);
#   E  HEALING through the same path: samples from the evidence log, the model, propagation of what the operator
#      already asserted (same source, same slot, same class), ONE new assertion, pack 1.1, restart: flowing again;
#   F  the accounting: every generated line is an evidence record; every usable event is a database row.
#
# Nothing here adds behaviour to the pipeline: it calls the same CLIs as every other step. The two apps are
# demo/live/flowgen.py and demo/live/sink.py (standard library only). ULPF_LIVE_INTERACTIVE=1 waits for the
# operator's choices from the UI's dropdowns instead of applying the scripted ones.
source "$(dirname "$(readlink -f "$0")")/../lib.sh"
cd "$ROOT"
LIVE="$STATE/live"; IN_PORT="${ULPF_LIVE_TCP_PORT:-6515}"; SINK_ADDR="${ULPF_LIVE_SINK:-127.0.0.1:8790}"; RATE="${ULPF_LIVE_RATE:-8}"
SRC="flowtap-01"; INTERACTIVE="${ULPF_LIVE_INTERACTIVE:-0}"
T_START=$(date +%s.%N)

stop_all() {
  [ -f "$LIVE/gen.control" ] && echo stop > "$LIVE/gen.control"
  touch "$LIVE/watch.stop" 2>/dev/null
  for f in runtime sink gen watch; do [ -f "$LIVE/$f.pid" ] && kill "$(cat "$LIVE/$f.pid")" 2>/dev/null; rm -f "$LIVE/$f.pid"; done
}
fail() { phase_set "$PHASE" failed "$1"; echo "---- live phase $PHASE FAILED: $1"; stop_all; exit 1; }
phase_set() { # id state [note]
  python3 - "$LIVE/status.json" "$1" "$2" "${3:-}" "${PHASE_TITLE:-}" <<'EOF'
import json, os, sys, time
path, pid, state, note, title = sys.argv[1:6]
try:
    st = json.load(open(path))
except Exception:
    st = {"run_id": time.strftime("%Y-%m-%dT%H:%M:%S"), "phases": {}}
p = st["phases"].setdefault(pid, {})
if title: p["title"] = title
if state == "running": p["started"] = time.time(); st["current"] = pid
if state in ("done", "failed") and p.get("started"): p["seconds"] = round(time.time() - p["started"], 1)
p["state"] = state
if note: p["note"] = note
st["updated"] = time.time()
json.dump(st, open(path + ".tmp", "w"), indent=1); os.replace(path + ".tmp", path)
EOF
}
phase() { PHASE="$1"; PHASE_TITLE="$2"; phase_set "$1" running; echo; echo "================ live $1: $2 ================"; }
phase_done() { PHASE_TITLE=""; phase_set "$PHASE" done "${1:-}"; echo "---- live $PHASE done: ${1:-}"; }
gen_ctl() { echo "$1" > "$LIVE/gen.control.tmp"; mv "$LIVE/gen.control.tmp" "$LIVE/gen.control"; }
cond() { python3 -c 'import json,sys
try: d = json.load(open(sys.argv[1]))
except Exception: sys.exit(1)
sys.exit(0 if eval(sys.argv[2]) else 1)' "$1" "$2"; }   # cond FILE "python expression over d"
watch_field() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2]))' "$LIVE/watch.json" "$1" 2>/dev/null; }
wait_for() { # seconds description command...
  local n=$1 what=$2; shift 2
  for _ in $(seq 1 $((n * 5))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.2; done
  fail "timed out after ${n}s waiting for: $what"
}

RUN_N=0
start_runtime() { # packs...
  RUN_N=$((RUN_N + 1)); local d="$LIVE/run-$RUN_N"; mkdir -p "$d"
  local args=(); for p in "$@"; do args+=(--pack "$p"); done
  freeport_check "$IN_PORT" || fail "port $IN_PORT busy"
  "$RT" run "${args[@]}" --source-id live-ingress-01 --listen "tcp:127.0.0.1:$IN_PORT" --idle-timeout 600s \
     --evidence "$LIVE/ev" --out "$d/out.jsonl" --quarantine "$d/q.jsonl" --forward "http://$SINK_ADDR/ingest" --forward-drain 10s 2> "$d/runtime.err" &
  echo $! > "$LIVE/runtime.pid"
  wait_for 10 "the runtime to listen on $IN_PORT" bash -c "! kill -0 \$(cat '$LIVE/runtime.pid') 2>/dev/null || ss -ltn | grep -q ':$IN_PORT '"
  kill -0 "$(cat "$LIVE/runtime.pid")" 2>/dev/null || { cat "$d/runtime.err"; fail "runtime #$RUN_N did not start"; }
  python3 - "$LIVE/status.json" "$RUN_N" "$@" <<'EOF'
import json, os, sys
path, n, packs = sys.argv[1], int(sys.argv[2]), sys.argv[3:]
st = json.load(open(path)); st["runtime"] = {"run": n, "packs": [json.load(open(p + "/pack.json"))["pack_id"] + " v" + json.load(open(p + "/pack.json"))["pack_version"] for p in packs]}
json.dump(st, open(path + ".tmp", "w"), indent=1); os.replace(path + ".tmp", path)
EOF
  echo "runtime #$RUN_N up on tcp:$IN_PORT with: $(for p in "$@"; do basename "$p"; done | tr '\n' ' ')  -> http://$SINK_ADDR/ingest"
}
stop_runtime() { # the generator is paused around a restart: no line sits in the socket buffer of a process that is going away
  gen_ctl pause; sleep 0.8
  local pid; pid=$(cat "$LIVE/runtime.pid"); kill -TERM "$pid" 2>/dev/null
  wait "$pid"; local rc=$?; rm -f "$LIVE/runtime.pid"
  grep -E '^\{' "$LIVE/run-$RUN_N/runtime.err" | tail -1 > "$LIVE/run-$RUN_N/stats.json"
  [ $rc -eq 0 ] || { tail -3 "$LIVE/run-$RUN_N/runtime.err"; fail "runtime #$RUN_N exited $rc (3 = delivery to the consumer still owed)"; }
  [ -s "$LIVE/run-$RUN_N/stats.json" ] || fail "runtime #$RUN_N printed no stats"
}

onboard() { # session samples  -> model (live) or the fixture fallback; the propagation store is the operator's
  local S=$1 samples=$2
  local args=(--samples "$samples" --source-id "$SRC" --operator op-014 --session "$S" --vendor none --propagation-store "$LIVE/propagation.json")
  if [ "$DEMO_PROVIDER" = "model" ]; then
    curl -s -m 3 "http://127.0.0.1:$LLAMA_PORT/health" | grep -q ok || fail "llama-server not up on $LLAMA_PORT (fallback: ULPF_DEMO_PROVIDER=fixture)"
    args+=(--provider model --model-id "$DEMO_MODEL" --server "http://127.0.0.1:$LLAMA_PORT" --mode whole --backend "cuda ngl=$LLAMA_NGL $MACHINE_LABEL")
  else
    echo "FALLBACK: team-authored proposals (demo/live/flowtap-proposals.json), not the model"
    args+=(--provider fixture --fixture "$ROOT/demo/live/flowtap-proposals.json")
  fi
  learn onboard "${args[@]}" > "$S.onboard.txt" 2>&1 || { tail -5 "$S.onboard.txt"; fail "onboard"; }
  cp "$S/session.json" "$S.before.json"
  learn certificates --session "$S" | grep -E "^cert_|^ +[0-9]+\.|resolved|UNRESOLVED|request" | head -40
}

# The operator's answers. There is no vendor document for an invented format, so the evidence is the operator's own
# statement, per field, recorded by name (provenance operator_assertion). Scripted = the truth about flowgen, queued
# exactly as the UI's dropdown queues a choice; interactive = wait for the UI.
resolve_by_assertion() { # session then "field=attribute|why" ...   (demo/live/assertions.py: the same `respond` CLI, scripted or from the UI)
  local S=$1; shift
  python "$ROOT/demo/live/assertions.py" "$S" "$LIVE" $([ "$INTERACTIVE" = "1" ] && echo --interactive) "$@" || fail "operator assertions"
}

# ------------------------------------------------------------------------------------------------ set-up
stop_all 2>/dev/null; pkill -f "demo/live/flowgen.py" 2>/dev/null; pkill -f "demo/live/sink.py" 2>/dev/null; pkill -f "tools/drift.py --watch" 2>/dev/null
chmod -R u+w "$LIVE" 2>/dev/null; rm -rf "$LIVE"; mkdir -p "$LIVE"
[ -f "$GOLDEN/pack.json.sig" ] || fail "golden pack unsigned (demo/reset.sh)"
python3 "$ROOT/demo/live/sink.py" --listen "$SINK_ADDR" --db "$LIVE/events.sqlite" --status "$LIVE/consumer.json" & echo $! > "$LIVE/sink.pid"
(cd learning && exec python tools/drift.py --watch "$LIVE/run-*" --json "$LIVE/watch.json" --window 40 --threshold 0.8 --min-frames 20 --interval 0.5 --stop-file "$LIVE/watch.stop") > "$LIVE/watch.log" 2>&1 & echo $! > "$LIVE/watch.pid"

phase A "An unknown source appears (nothing is guessed, every byte is kept)"
start_runtime "$GOLDEN"
gen_ctl run
python3 "$ROOT/demo/live/flowgen.py" --to "127.0.0.1:$IN_PORT" --rate "$RATE" --status "$LIVE/generator.json" --control "$LIVE/gen.control" & echo $! > "$LIVE/gen.pid"
wait_for 30 "the monitor to report the unknown source" cond "$LIVE/watch.json" 'd["fired"]' 
SIG1=$(python3 -c 'import json,sys; w=json.load(open(sys.argv[1])); print(w["signals"]["unknown_signatures"][0]["key"])' "$LIVE/watch.json")
grep -a "FIRED" "$LIVE/watch.log" | tail -1
phase_done "every line quarantined as unknown signature $SIG1"

phase B "Live onboarding from the evidence log (model proposes, certificates fire, operator asserts)"
(cd learning && python tools/drift.py --quarantine "$LIVE/run-1/q.jsonl" --evidence "$LIVE/ev" --extract-signature "$SIG1" --limit 24 --out "$LIVE/samples-v1.log") || fail "extract samples from the evidence store"
onboard "$LIVE/session-v1" "$LIVE/samples-v1.log"
python3 - "$LIVE/session-v1.before.json" <<'EOF' || fail "the certificates the demo is built around did not fire (see live/session-v1.onboard.txt)"
import json, sys
s = json.load(open(sys.argv[1])); c = s["certificates"]
cls = lambda k: (c.get(f"cert_flowtap-01_pos{k}") or {}).get("evidence", {}).get("discriminator", {}).get("ambiguity_class")
ok = s["proposal"]["event_class_uid"] == 4001 and cls(4) == cls(6) == "endpoint_orientation" and cls(1) == "temporal_role" and len(s["verdict"]["blockers"]) == 4 and s["state"] == "awaiting_evidence"
print(f"class {s['proposal']['event_class_uid']}; certificates {len(c)}: " + ", ".join(f"{k[-4:]}={v['evidence']['discriminator'].get('ambiguity_class') or v['status']}" for k, v in c.items()) + f"; unevidenced {[u['field'] for u in s['unevidenced']]}; blockers {len(s['verdict']['blockers'])}")
print(f"the system's own request: {s['pending_request']['discriminator_id']} — a document that does not exist for this source")
sys.exit(0 if ok else 1)
EOF
# the four MANDATORY ones first (these are what blocks promotion), then the rest of what the operator knows about their own
# sensor: an unasserted column keeps the model's label with provenance model_proposal, and two columns given the same label
# make a pack the contract refuses (found with the live 4B on the v2 format: dst_endpoint.port proposed twice)
resolve_by_assertion "$LIVE/session-v1" \
  "pos_4=src_endpoint.ip|flowtap writes the initiator first" \
  "pos_6=dst_endpoint.ip|the second address is the responder" \
  "pos_1=time|flowtap stamps the line when the flow is logged: it is the event time" \
  "pos_2=action_id|the verdict code: 1 allowed, 2 denied — the same codes OCSF uses" \
  "pos_5=src_endpoint.port|the initiator's port follows its address" \
  "pos_7=dst_endpoint.port|the responder's port follows its address" \
  "pos_3=connection_info.protocol_name|tcp or udp" \
  "pos_8=traffic.bytes_out|first counter: bytes from the initiator" \
  "pos_9=traffic.bytes_in|second counter: bytes to the initiator"
learn promote --session "$LIVE/session-v1" --out "$LIVE/packs/flowtap-v1" --pack-id "$SRC" | tee "$LIVE/promote-v1.txt" || fail "promote"
"$RT" verify-pack --pack "$LIVE/packs/flowtap-v1" || fail "verify-pack"
phase_done "promoted: $(python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); print(len(s["certificates"]), "certificates,", s["metrics"]["operator_responses"], "operator assertions, signed pack")' "$LIVE/session-v1/session.json")"

phase C "The pack is loaded: events flow to the consumer's database"
stop_runtime
start_runtime "$GOLDEN" "$LIVE/packs/flowtap-v1"
gen_ctl run
wait_for 40 "parse success to recover" cond "$LIVE/watch.json" 'd["state"] == "ok" and d["by_family"].get("positional-9", 0) >= 40' 
wait_for 20 "rows in the consumer's database" cond "$LIVE/consumer.json" 'd["rows"] >= 40' 
phase_done "parse success $(watch_field parse_success) over the last 40 frames; $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["rows"])' "$LIVE/consumer.json") rows in SQLite"

phase D "Drift: the generator changes its format mid-run"
gen_ctl drift
wait_for 40 "the drift monitor to fire" cond "$LIVE/watch.json" 'd["fired"]' 
sleep 2
SIG2=$(python3 -c 'import json,sys; w=json.load(open(sys.argv[1])); print(w["signals"]["unknown_signatures"][0]["key"])' "$LIVE/watch.json")
grep -a "FIRED" "$LIVE/watch.log" | tail -1
[ "$SIG2" != "$SIG1" ] || fail "the monitor fired on the old signature"
phase_done "monitor fired: parse success $(watch_field parse_success); new unknown signature $SIG2"

phase E "Healing through the same path (samples from the evidence log, propagation, two assertions)"
(cd learning && python tools/drift.py --quarantine "$LIVE/run-$RUN_N/q.jsonl" --evidence "$LIVE/ev" --extract-signature "$SIG2" --limit 24 --out "$LIVE/samples-v2.log") || fail "extract v2 samples"
onboard "$LIVE/session-v2" "$LIVE/samples-v2.log"
python3 - "$LIVE/session-v2.before.json" <<'EOF' || fail "propagation did not carry the operator's earlier assertions"
import json, sys
s = json.load(open(sys.argv[1]))
prop = sorted(h["slot_index"] + 1 for h in s.get("propagated", []))
print(f"propagated without a question (same source, slot, class): slots {prop} -> {[a for h in s['propagated'] for a in h['attributes']]}; still blocking: {s['verdict']['blockers']}")
sys.exit(0 if prop == [2, 3, 4, 5, 6, 7, 8, 9] and len(s["verdict"]["blockers"]) == 1 and "time" in s["verdict"]["blockers"][0] else 1)
EOF
resolve_by_assertion "$LIVE/session-v2" "pos_1=time|firmware 2.0 writes the same event time as ISO 8601" "pos_10=src_endpoint.zone|the new column: the initiator's zone"
learn promote --session "$LIVE/session-v2" --out "$LIVE/packs/flowtap-v2" --pack-id "$SRC-fw2" | tee "$LIVE/promote-v2.txt" || fail "promote v2"
learn merge "$LIVE/packs/flowtap-v1" "$LIVE/packs/flowtap-v2" --out "$LIVE/packs/flowtap-source-1.1" --pack-id "$SRC" --pack-version 1.1 || fail "merge"
"$RT" verify-pack --pack "$LIVE/packs/flowtap-source-1.1" || fail "verify merged pack"
stop_runtime
start_runtime "$GOLDEN" "$LIVE/packs/flowtap-source-1.1"
gen_ctl run
wait_for 40 "parse success to recover after healing" cond "$LIVE/watch.json" 'd["state"] == "ok" and d["by_family"].get("positional-10", 0) >= 40' 
grep -a "RECOVERED" "$LIVE/watch.log" | tail -1
phase_done "healed: 8 columns propagated, $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["metrics"]["operator_responses"])' "$LIVE/session-v2/session.json") new assertions (10 mapping decisions by hand); parse success $(watch_field parse_success)"

phase F "Backfill: the quarantined bytes, replayed from the evidence log through the healed pack"
gen_ctl finish
wait_for 30 "the generator to deliver its backlog and exit" bash -c "! kill -0 $(cat "$LIVE/gen.pid") 2>/dev/null"
GEN=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sent"])' "$LIVE/generator.json")
wait_for 30 "the runtime to have framed all $GEN lines" cond "$LIVE/watch.json" "d['frames_total'] == $GEN" 
sleep 1; stop_runtime; touch "$LIVE/watch.stop"
# Everything that was quarantined while nobody could read it is still in the evidence log. There is no first-class
# "re-ingest from evidence" command: this is the existing pieces — the monitor's extraction (raw_hash checked) and an
# ordinary `run --input` under the healed pack, into its OWN evidence store, delivered to the same consumer. The link
# between a backfilled row and the original evidence record is the raw_hash, checked below by value.
: > "$LIVE/backfill.log"
for d in "$LIVE"/run-*; do
  for sig in "$SIG1" "$SIG2"; do
    (cd learning && python tools/drift.py --quarantine "$d/q.jsonl" --evidence "$LIVE/ev" --extract-signature "$sig" --out "$LIVE/backfill.part" 2>/dev/null) > /dev/null && cat "$LIVE/backfill.part" >> "$LIVE/backfill.log"
  done
done
rm -f "$LIVE/backfill.part"; mkdir -p "$LIVE/backfill"
"$RT" run --pack "$GOLDEN" --pack "$LIVE/packs/flowtap-source-1.1" --source-id live-backfill-01 --input "$LIVE/backfill.log" --evidence "$LIVE/ev-backfill" \
   --out "$LIVE/backfill/out.jsonl" --quarantine "$LIVE/backfill/q.jsonl" --forward "http://$SINK_ADDR/ingest" --forward-drain 20s 2> "$LIVE/backfill/runtime.err" || { tail -3 "$LIVE/backfill/runtime.err"; fail "backfill run"; }
grep -E '^\{' "$LIVE/backfill/runtime.err" | tail -1 > "$LIVE/backfill/stats.json"
phase_done "$(python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); print(s["frames"], "quarantined lines replayed from the evidence log:", s["usable"], "usable,", s["quarantined"], "still quarantined")' "$LIVE/backfill/stats.json")"

phase G "The accounting: every line is evidence, every line is a row"
python3 - "$LIVE" "$GEN" <<'EOF' | tee "$LIVE/summary.txt"
import glob, json, sqlite3, sys
L, gen = sys.argv[1], int(sys.argv[2])
runs = [json.load(open(p)) for p in sorted(glob.glob(f"{L}/run-*/stats.json"))]
frames, usable, quar = (sum(r[k] for r in runs) for k in ("frames", "usable", "quarantined"))
delivered = sum(e.get("delivered_events", 0) for r in runs for e in (r.get("egress") or []))
bf = json.load(open(f"{L}/backfill/stats.json"))
qhash = {json.loads(l)["raw_hash"] for p in glob.glob(f"{L}/run-*/q.jsonl") for l in open(p)}
bfhash = [json.loads(l)["_lineage"]["raw_hash"] for l in open(f"{L}/backfill/out.jsonl")]
linked = all(h in qhash for h in bfhash)
rows = sqlite3.connect(f"{L}/events.sqlite").execute("SELECT COUNT(*) FROM events").fetchone()[0]
fam = dict(sqlite3.connect(f"{L}/events.sqlite").execute("SELECT family, COUNT(*) FROM events GROUP BY family").fetchall())
w = json.load(open(f"{L}/watch.json"))
fired = [e for e in w["events"] if e["state"] == "fired"]; rec = [e for e in w["events"] if e["state"] == "ok"]
print(f"generator sent {gen}  |  evidence records {frames} = live usable {usable} + quarantined-and-retained {quar}  |  backfilled from evidence {bf['usable']} of {bf['frames']} (raw_hash linked: {linked})  |  SQLite rows {rows} {fam}")
print(f"drift monitor: fired {len(fired)}x, recovered {len(rec)}x; runtime restarts {len(runs) - 1}; gap records {sum(r['gap_records'] for r in runs)}")
ok = (gen == frames == usable + quar and bf["frames"] == quar and bf["quarantined"] == 0 and linked and rows == usable + bf["usable"] == gen
      and len(fired) == 2 and len(rec) == 2 and set(fam) == {"positional-9", "positional-10"})
json.dump({"generated": gen, "frames": frames, "usable": usable, "quarantined": quar, "backfilled": bf["usable"], "backfill_linked_by_raw_hash": linked, "rows": rows, "by_family": fam, "monitor_fired": len(fired), "monitor_recovered": len(rec), "ok": ok}, open(f"{L}/summary.json", "w"), indent=1)
sys.exit(0 if ok else 1)
EOF
[ ${PIPESTATUS[0]} -eq 0 ] || fail "the accounting does not balance (live/summary.txt)"
phase_done "$(head -1 "$LIVE/summary.txt")"
stop_all
echo "live sequence: $(python3 -c "import sys; print(round($(date +%s.%N) - $T_START, 1))")s"

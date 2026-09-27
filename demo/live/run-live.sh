#!/usr/bin/env bash
# The LIVE sequence (parallel to the six rehearsed steps; everything it writes is under $STATE/live):
#
#   flowgen x2 (generator apps) --syslog/TCP + HTTP POST--> ONE ULPF runtime --bounded spool--> THREE destinations, each with its own cursor:
#        SIEM (bulk encoding over HTTP; here demo/siem/fake_bulk.py, the contract-checked stand-in for OpenSearch),
#        data lake (adapters/lake/lakewriter.py: OCSF Parquet, Security Lake layout) and stdout -> a file
#
#   A  an unrecognised source arrives: quarantined, bytes kept, nothing parsed or guessed — UNTIL A HUMAN SAYS "onboard this" (Tier 1)
#   B  onboarding, automatic from there except for ambiguity: samples out of the evidence log, the model, certificates, the
#      operator's assertions, a signed pack, HOT-LOADED (SIGHUP; the activation is an evidence-log record) — no restart, no pause
#   C  flowing: two ingress connectors, two egress connectors, typed OCSF values in somebody else's database
#   D  EGRESS OUTAGE: the SIEM is killed; ingestion continues AND THE LAKE KEEPS FLOWING (its own cursor); the SIEM falls
#      behind, the outage is an evidence leaf; on restart its backlog is delivered from its cursor, no document twice (_id)
#   E  DRIFT on both generators: the monitor fires; the source HEALS ITSELF (tools/autoheal.py) — 8 of 10 columns on the operator's
#      earlier evidence, pack 1.1, an alert; the 2 columns nobody has evidence for are WITHHELD and asked, never guessed
#   F  the operator answers those two: pack 1.2
#   G  backfill from the evidence log;  H  the accounting;  I  whitespace drift, the case no policy can heal
#
# The two apps are demo/live/flowgen.py and demo/apps/database.py (standard library only). This sequence is SCRIPTED — it is the
# repeatable gate (twice-live.sh). The interactive demo, driven by buttons on three pages, is demo/start-demo.sh.
source "$(dirname "$(readlink -f "$0")")/../lib.sh"
cd "$ROOT"
LIVE="$STATE/live"; IN_PORT="${ULPF_LIVE_TCP_PORT:-6515}"; SINK_ADDR="${ULPF_LIVE_SINK:-127.0.0.1:8790}"; LAKE_ADDR="${ULPF_LIVE_LAKE:-127.0.0.1:8792}"; RATE="${ULPF_LIVE_RATE:-8}"
SRC="flowtap-01"; INTERACTIVE=0   # scripted only: the interactive demo is demo/start-demo.sh (three apps, three pages)
T_START=$(date +%s.%N)

stop_all() {
  [ -f "$LIVE/gen.control" ] && echo stop > "$LIVE/gen.control"
  touch "$LIVE/watch.stop" 2>/dev/null
  for f in runtime sink lake gen gen2 watch; do [ -f "$LIVE/$f.pid" ] && kill "$(cat "$LIVE/$f.pid")" 2>/dev/null; rm -f "$LIVE/$f.pid"; done
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

HTTP_PORT="${ULPF_LIVE_HTTP_PORT:-8516}"
start_runtime() { # ONE runtime for the whole sequence: two ingress connectors, two egress connectors, packs hot-reloaded from packs.txt
  local d="$LIVE/run-1"; mkdir -p "$d"; : > "$LIVE/packs.txt"
  freeport_check "$IN_PORT" || fail "port $IN_PORT busy"; freeport_check "$HTTP_PORT" || fail "port $HTTP_PORT busy"
  "$RT" run --pack "$GOLDEN" --packs-file "$LIVE/packs.txt" --source-id live-ingress-01 --listen "tcp:127.0.0.1:$IN_PORT" --listen "http:127.0.0.1:$HTTP_PORT" --idle-timeout 600s \
     --evidence "$LIVE/ev" --out "$d/out.jsonl" --quarantine "$d/q.jsonl" --spool "$LIVE/spool" --spool-cap 256MiB --spool-segment 16MiB \
     --forward "bulk+http://$SINK_ADDR" --forward "http://$LAKE_ADDR/ingest" --forward "stdout:" --forward-stall-after 2s --forward-drain 15s \
     > "$d/egress-stdout.ndjson" 2> "$d/runtime.err" &
  echo $! > "$LIVE/runtime.pid"
  wait_for 10 "the runtime to listen" bash -c "! kill -0 \$(cat '$LIVE/runtime.pid') 2>/dev/null || { ss -ltn | grep -q ':$IN_PORT ' && ss -ltn | grep -q ':$HTTP_PORT '; }"
  kill -0 "$(cat "$LIVE/runtime.pid")" 2>/dev/null || { cat "$d/runtime.err"; fail "runtime did not start"; }
  packs_status
  echo "runtime up: ingress syslog/TCP :$IN_PORT + HTTP :$HTTP_PORT  ->  bounded spool -> SIEM (bulk $SINK_ADDR) + lake (HTTP $LAKE_ADDR) + stdout (run-1/egress-stdout.ndjson)"
}
packs_status() { python3 - "$LIVE" "$GOLDEN" <<'EOF'
import json, os, sys
L, golden = sys.argv[1:3]
dirs = [golden] + [l.strip() for l in open(f"{L}/packs.txt") if l.strip()]
st = json.load(open(f"{L}/status.json")); docs = [json.load(open(d + "/pack.json")) for d in dirs]
st["runtime"] = {"run": 1, "packs": [f"{p['pack_id']} v{p['pack_version']}" for p in docs], "ingress": ["syslog/TCP", "HTTP POST"], "egress": ["SIEM: bulk over HTTP", "data lake: HTTP -> Parquet", "stdout -> file"]}
json.dump(st, open(f"{L}/status.json.tmp", "w"), indent=1); os.replace(f"{L}/status.json.tmp", f"{L}/status.json")
EOF
}
reload_packs() { # pack dirs... -> packs.txt, SIGHUP; the runtime swaps between two frames and records pack_activated in the evidence log
  local before; before=$(grep -ac "^reloaded:" "$LIVE/run-1/runtime.err")
  printf '%s\n' "$@" > "$LIVE/packs.txt.tmp"; mv "$LIVE/packs.txt.tmp" "$LIVE/packs.txt"
  kill -HUP "$(cat "$LIVE/runtime.pid")"
  wait_for 10 "the runtime to reload" bash -c "[ \$(grep -ac '^reloaded:' '$LIVE/run-1/runtime.err') -gt $before ] || grep -aq 'reload REFUSED' '$LIVE/run-1/runtime.err'"
  grep -aq "reload REFUSED" "$LIVE/run-1/runtime.err" && { grep -a "reload REFUSED" "$LIVE/run-1/runtime.err"; fail "the runtime refused the pack"; }
  packs_status
}
wait_reloads() { wait_for 15 "the runtime to reload" bash -c "[ \$(grep -ac '^reloaded:' '$LIVE/run-1/runtime.err') -ge $1 ]"; packs_status; }
gaps_json() { local t="$LIVE/gaps.json.$BASHPID.tmp"; "$VF" gaps --evidence "$LIVE/ev" --trust keys/trust --json 2>/dev/null > "$t" && mv "$t" "$LIVE/gaps.json"; }
gap_count() { gaps_json; python3 -c 'import json,sys; print(sum(1 for l in open(sys.argv[1]) if l.strip() and json.loads(l)["record"]["kind"] == sys.argv[2]))' "$LIVE/gaps.json" "$1" 2>/dev/null || echo 0; }
start_sink() { python3 "$ROOT/demo/siem/fake_bulk.py" --listen "$SINK_ADDR" --state "$LIVE/siem-state.json" --status "$LIVE/siem.json" & echo $! > "$LIVE/sink.pid"; }
start_lake() { python "$ROOT/adapters/lake/lakewriter.py" --lake "$LIVE/lake" --listen "$LAKE_ADDR" --rotate-seconds 5 --status "$LIVE/lake.json" > "$LIVE/lake.log" 2>&1 & echo $! > "$LIVE/lake.pid"; }
siem_docs() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["unique_documents"])' "$LIVE/siem.json"; }
lake_rows() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["received_rows"])' "$LIVE/lake.json"; }
provider_args() {
  if [ "$DEMO_PROVIDER" = "model" ]; then
    curl -s -m 3 "http://127.0.0.1:$LLAMA_PORT/health" | grep -q ok || fail "llama-server not up on $LLAMA_PORT (fallback: ULPF_DEMO_PROVIDER=fixture)"
    PROV=(--provider model --model-id "$DEMO_MODEL" --server "http://127.0.0.1:$LLAMA_PORT" --backend "cuda ngl=$LLAMA_NGL $MACHINE_LABEL")
  else
    echo "FALLBACK: team-authored proposals (demo/live/flowtap-proposals.json), not the model"
    PROV=(--provider fixture --fixture "$ROOT/demo/live/flowtap-proposals.json")
  fi
}

onboard() { # session samples
  local S=$1 samples=$2; provider_args
  local extra=(); [ "$DEMO_PROVIDER" = "model" ] && extra=(--mode whole)
  learn onboard --samples "$samples" --source-id "$SRC" --operator op-014 --session "$S" --vendor flowtap --product "flowtap flow sensor (demo generator)" --transport-hint syslog-tcp \
        --propagation-store "$LIVE/propagation.json" "${PROV[@]}" "${extra[@]}" > "$S.onboard.txt" 2>&1 || { tail -5 "$S.onboard.txt"; fail "onboard"; }
  cp "$S/session.json" "$S.before.json"
  learn certificates --session "$S" | grep -E "^cert_|resolved|UNRESOLVED" | head -20
}
resolve_by_assertion() { # session then "field=attribute|why" ...   (demo/live/assertions.py: the same `respond` CLI, scripted or from the UI)
  local S=$1; shift
  python "$ROOT/demo/live/assertions.py" "$S" "$LIVE" $([ "$INTERACTIVE" = "1" ] && echo --interactive) "$@" || fail "operator assertions"
}
# THE TIER 1 MOMENT: the only place a human is structurally required for a new source. Nothing is onboarded from traffic that
# merely arrived; a named operator says "onboard this". Interactive: the button on the System page. Scripted: the same record, after a pause.
wait_for_decision() { # signature events
  python3 - "$LIVE" "$1" "$2" <<'EOF'
import json, os, sys
L, sig, n = sys.argv[1:4]
json.dump({"decision_needed": {"signature": sig, "events": int(n), "question": "An unrecognised source is sending. Every line is quarantined with its bytes kept; nothing was parsed, nothing was guessed. Onboard it?"}}, open(f"{L}/pending.json.tmp", "w"))
os.replace(f"{L}/pending.json.tmp", f"{L}/pending.json")
EOF
  : > "$LIVE/decisions.jsonl"
  if [ "$INTERACTIVE" = "1" ]; then echo ">>> WAITING FOR A HUMAN: press 'onboard this source' on the System page, http://localhost:8765/live.html (nothing happens until then — by design)"
  else echo ">>> waiting for a human decision (scripted: op-014 decides after ${ULPF_LIVE_DECISION_PAUSE:-5}s; the stream keeps quarantining meanwhile)"
       ( sleep "${ULPF_LIVE_DECISION_PAUSE:-5}"; echo '{"onboard": true, "by": "script"}' >> "$LIVE/decisions.jsonl" ) & fi
  wait_for 900 "a human to say 'onboard this'" grep -q '"onboard": true' "$LIVE/decisions.jsonl"
  python3 - "$LIVE" "$1" <<'EOF'
import json, os, sys, time
L, sig = sys.argv[1:3]
w = json.load(open(f"{L}/watch.json"))
rec = {"decision": "onboard", "tier": 1, "operator_id": "op-014", "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "signature": sig, "quarantined_when_decided": w["quarantined_total"], "usable_when_decided": w["usable_total"]}
open(f"{L}/tier1-decision.json", "w").write(json.dumps(rec, indent=1) + "\n"); os.replace(f"{L}/pending.json", f"{L}/pending.prev.json")
print(f"TIER 1 DECISION recorded: operator {rec['operator_id']} onboards {sig[:60]}… — {rec['quarantined_when_decided']} lines were quarantined while nobody had decided, {rec['usable_when_decided']} parsed")
EOF
}

# ------------------------------------------------------------------------------------------------ set-up
stop_all 2>/dev/null; pkill -f "demo/live/flowgen.py" 2>/dev/null; pkill -f "demo/siem/[f]ake_bulk.py" 2>/dev/null; pkill -f "adapters/lake/[l]akewriter.py" 2>/dev/null; pkill -f "tools/drift.py --watch" 2>/dev/null
chmod -R u+w "$LIVE" 2>/dev/null; rm -rf "$LIVE"; mkdir -p "$LIVE"
[ -f "$GOLDEN/pack.json.sig" ] || fail "golden pack unsigned (demo/reset.sh)"
start_sink; start_lake
wait_for 20 "the SIEM stand-in and the lake writer" bash -c "[ -s '$LIVE/siem.json' ] && [ -s '$LIVE/lake.json' ]"
(cd learning && exec python tools/drift.py --watch "$LIVE/run-*" --json "$LIVE/watch.json" --window 40 --threshold 0.8 --min-frames 20 --interval 0.5 --stop-file "$LIVE/watch.stop") > "$LIVE/watch.log" 2>&1 & echo $! > "$LIVE/watch.pid"
( while [ ! -f "$LIVE/watch.stop" ]; do gaps_json; sleep 1; done ) &   # the UI lists outages and pack changes as they become evidence records

phase A "An unrecognised source arrives: quarantined, bytes kept, nothing guessed — until a human decides"
phase_set A running; start_runtime
gen_ctl run
python3 "$ROOT/demo/live/flowgen.py" --to "127.0.0.1:$IN_PORT" --rate "$RATE" --seed 26156 --status "$LIVE/generator.json" --control "$LIVE/gen.control" & echo $! > "$LIVE/gen.pid"
python3 "$ROOT/demo/live/flowgen.py" --to "http://127.0.0.1:$HTTP_PORT/" --rate "$(python3 -c "print($RATE/2)")" --seed 561 --status "$LIVE/generator-http.json" --control "$LIVE/gen.control" & echo $! > "$LIVE/gen2.pid"
wait_for 30 "the monitor to report the unknown source" cond "$LIVE/watch.json" 'd["fired"]'
SIG1=$(python3 -c 'import json,sys; w=json.load(open(sys.argv[1])); print(w["signals"]["unknown_signatures"][0]["key"])' "$LIVE/watch.json")
grep -a "FIRED" "$LIVE/watch.log" | tail -1
cond "$LIVE/watch.json" 'd["usable_total"] == 0' || fail "something was parsed before anybody decided"
wait_for_decision "$SIG1" "$(watch_field quarantined_total)"
phase_done "quarantined until op-014 said 'onboard this': $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["quarantined_when_decided"])' "$LIVE/tier1-decision.json") lines kept, 0 parsed, 0 guessed"

phase B "Onboarding — automatic from here, except where a field is ambiguous"
(cd learning && python tools/drift.py --quarantine "$LIVE/run-1/q.jsonl" --evidence "$LIVE/ev" --extract-signature "$SIG1" --limit 24 --out "$LIVE/samples-v1.log") || fail "extract samples from the evidence store"
onboard "$LIVE/session-v1" "$LIVE/samples-v1.log"
python3 - "$LIVE/session-v1.before.json" <<'EOF' || fail "the certificates the demo is built around did not fire (see live/session-v1.onboard.txt)"
import json, sys
s = json.load(open(sys.argv[1])); c = s["certificates"]
cls = lambda k: (c.get(f"cert_flowtap-01_pos{k}") or {}).get("evidence", {}).get("discriminator", {}).get("ambiguity_class")
req = s["pending_request"]
ok = s["proposal"]["event_class_uid"] == 4001 and cls(4) == cls(6) == "endpoint_orientation" and cls(1) == "temporal_role" and len(s["verdict"]["blockers"]) == 4 and req["discriminator_id"] == "operator_assertion"
print(f"class {s['proposal']['event_class_uid']}; certificates {len(c)}: " + ", ".join(f"{k.split('_')[-1]}={v['evidence']['discriminator'].get('ambiguity_class') or v['status']}" for k, v in c.items()) + f"; blockers {len(s['verdict']['blockers'])}")
print(f"the system's request: {req['discriminator_id']} — {req['text'][:150]}…")
sys.exit(0 if ok else 1)
EOF
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
learn promote --session "$LIVE/session-v1" --out "$LIVE/packs/flowtap-v1" --pack-id "$SRC" --withhold-unevidenced | tee "$LIVE/promote-v1.txt" || fail "promote"
"$RT" verify-pack --pack "$LIVE/packs/flowtap-v1" || fail "verify-pack"
reload_packs "$LIVE/packs/flowtap-v1"
phase_done "promoted and HOT-LOADED (no restart, the generators never paused): $(python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); print(len(s["certificates"]), "certificates,", s["metrics"]["operator_responses"], "assertions,", s["metrics"]["evidence_requests"], "evidence request(s)")' "$LIVE/session-v1/session.json")"

phase C "Flowing: two ingress connectors in, two egress connectors out"
wait_for 40 "parse success to recover" cond "$LIVE/watch.json" 'd["state"] == "ok" and d["by_family"].get("positional-9", 0) >= 60'
wait_for 20 "documents in the SIEM" cond "$LIVE/siem.json" 'd["unique_documents"] >= 60'
wait_for 20 "rows at the lake writer" cond "$LIVE/lake.json" 'd["received_rows"] >= 60'
python3 - "$LIVE" <<'EOF' || fail "both ingress connectors and both egress connectors must have carried events"
import json, sys
L = sys.argv[1]
ch = {}
for l in open(f"{L}/ev/seg_00000.idx.jsonl"):
    r = json.loads(l); ch[r["ingest_channel"]] = ch.get(r["ingest_channel"], 0) + 1
e = [json.loads(l) for l in open(f"{L}/run-1/out.jsonl")][-1]
std = sum(1 for _ in open(f"{L}/run-1/egress-stdout.ndjson"))
print("evidence records by ingress connector:", {k: v for k, v in ch.items() if not k.startswith(("egress", "control"))}, "| stdout egress lines:", std)
print("an event as the destinations receive it:", json.dumps({k: e[k] for k in ("time", "action_id", "src_endpoint", "dst_endpoint", "traffic", "metadata")}), "| event_time", e["_lineage"]["event_time"])
ok = (sum(1 for k in ch if k.startswith("tcp:")) == 1 and sum(1 for k in ch if k.startswith("http:")) == 1 and std > 0 and isinstance(e["time"], int) and e["_lineage"]["event_time"] == e["time"] > 10**12
      and isinstance(e["action_id"], int) and isinstance(e["src_endpoint"]["port"], int) and e["metadata"]["product"]["vendor_name"] == "flowtap")
sys.exit(0 if ok else 1)
EOF
phase_done "parse success $(watch_field parse_success); SIEM $(siem_docs) documents, lake $(lake_rows) rows; typed values, the pack names flowtap"

phase D "Egress outage: the SIEM dies, ingestion does not, the LAKE KEEPS FLOWING; the outage is an evidence leaf; the SIEM's backlog arrives from its cursor"
DOCS0=$(siem_docs); LAKE0=$(lake_rows); USABLE0=$(watch_field usable_total)
kill "$(cat "$LIVE/sink.pid")"; wait "$(cat "$LIVE/sink.pid")" 2>/dev/null; rm -f "$LIVE/sink.pid"; echo "SIEM KILLED at $DOCS0 documents (its state is kept, as OpenSearch's container keeps its data)"
sleep 0.5
cursors() { python3 -c 'import glob,json,sys; c={json.load(open(p))["sink"]: json.load(open(p))["delivered_events"] for p in glob.glob(sys.argv[1]+"/spool/cursor-*.json")}; print(next(v for k,v in c.items() if k.startswith("bulk+")), next(v for k,v in c.items() if "/ingest" in k))' "$LIVE"; }
read SIEMCUR0 LAKECUR0 < <(cursors)
for _ in $(seq 1 150); do [ "$(gap_count egress_stalled)" -ge 1 ] && break; sleep 0.2; done
[ "$(gap_count egress_stalled)" -ge 1 ] || fail "no egress_stalled record in the evidence log"
wait_for 30 "ingestion to continue while the SIEM is down" cond "$LIVE/watch.json" "d['usable_total'] >= $USABLE0 + 40 and d['state'] == 'ok'"
wait_for 20 "the lake to keep flowing while the SIEM is down" cond "$LIVE/lake.json" "d['received_rows'] >= $LAKE0 + 40"
"$VF" gaps --evidence "$LIVE/ev" --trust keys/trust 2>/dev/null | grep -a "egress_stalled" | head -1 | cut -c1-220
python3 - "$LIVE" "$DOCS0" "$SIEMCUR0" "$LAKECUR0" <<'EOF' || fail "during the outage the SIEM's cursor must not move while the lake's keeps up with ingestion"
import glob, json, sys
L, docs0, siem0, lake0 = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
w = json.load(open(f"{L}/watch.json")); usable = w["usable_total"]
cur = {json.load(open(p))["sink"]: json.load(open(p))["delivered_events"] for p in glob.glob(f"{L}/spool/cursor-*.json")}
siem = next(v for k, v in cur.items() if k.startswith("bulk+")); lake = next(v for k, v in cur.items() if "/ingest" in k)
print(f"during the outage: SIEM ahead-by {max(0, usable - siem)}, lake ahead-by {max(0, usable - lake)} (usable {usable}; the SIEM still holds {docs0} documents)")
print(f"  SIEM cursor {siem0} -> {siem} (must not move while it is down); lake cursor {lake0} -> {lake} (must advance and stay current)")
sys.exit(0 if siem == siem0 and lake > lake0 and usable - lake <= 20 else 1)   # the 40 more events ingested meanwhile are the wait_for above
EOF
echo "SIEM down: ULPF ingested $(( $(watch_field usable_total) - USABLE0 )) more events; the lake got $(( $(lake_rows) - LAKE0 )) of them meanwhile. Restarting the SIEM…"
start_sink
wait_for 60 "the SIEM's backlog to be delivered from its cursor" cond "$LIVE/siem.json" "d['unique_documents'] >= $(watch_field usable_total) - 12 and d['unique_documents'] > $DOCS0 + 40"
for _ in $(seq 1 100); do [ "$(gap_count egress_resumed)" -ge 1 ] && break; sleep 0.2; done
[ "$(gap_count egress_resumed)" -ge 1 ] || fail "no egress_resumed record"
"$VF" gaps --evidence "$LIVE/ev" --trust keys/trust 2>/dev/null | grep -a "egress_resumed" | head -1 | cut -c1-220
phase_done "SIEM outage recorded as an evidence leaf; the lake kept flowing; SIEM documents $DOCS0 -> $(siem_docs) after the catch-up; nothing dropped, nothing stored twice"

phase E "Drift across the fleet: the monitor fires and the source HEALS ITSELF — with an alert, not a prompt"
gen_ctl drift
wait_for 40 "the drift monitor to fire" cond "$LIVE/watch.json" 'd["fired"]'
sleep 2
SIG2=$(python3 -c 'import json,sys; w=json.load(open(sys.argv[1])); print(w["signals"]["unknown_signatures"][0]["key"])' "$LIVE/watch.json")
grep -a "FIRED" "$LIVE/watch.log" | tail -1
[ "$SIG2" != "$SIG1" ] || fail "the monitor fired on the old signature"
provider_args
RELOADS=$(grep -ac "^reloaded:" "$LIVE/run-1/runtime.err")
(cd learning && python tools/autoheal.py heal --source-id "$SRC" --signature "$SIG2" --run-dir "$LIVE/run-1" --evidence "$LIVE/ev" --family-pack "$LIVE/packs/flowtap-v1" \
   --propagation-store "$LIVE/propagation.json" --work "$LIVE/autoheal" --packs-file "$LIVE/packs.txt" --runtime-pid "$(cat "$LIVE/runtime.pid")" --pack-version 1.1 \
   --vendor flowtap --product "flowtap flow sensor (demo generator)" --transport-hint syslog-tcp "${PROV[@]}") 2>&1 | tail -3 || fail "auto-heal"
wait_reloads $((RELOADS + 1))
python3 - "$LIVE/autoheal/alert-latest.json" <<'EOF' || fail "the alert does not say what the policy requires"
import json, sys
a = json.load(open(sys.argv[1]))
prop = sorted(p["slot"] for p in a["propagated"]); held = sorted(w["slot"] for w in a["withheld"])
print(f"ALERT: {a['outcome']}")
print(f"  bound to the onboarded source: {a['source_binding']['drifted_from']} within {a['source_binding']['source_known_from']}")
print(f"  propagated (no question): slots {prop}; auto-promoted: {[m['attribute'] for m in a['auto_promoted']]}")
print(f"  WITHHELD, operator asked: " + "; ".join(f"slot {w['slot']} ({w['why_withheld']})" for w in a["withheld"]))
print(f"  pack {a['pack']['pack_id']} v{a['pack']['pack_version']} {a['pack']['sha256'][:23]}…  rollback: {a['rollback']['command'][:80]}…")
ok = a["source_binding"]["bound"] and prop == [1, 2, 4, 5, 6, 7, 8, 9] and held == [3, 10] and all(m["provenance"] != "model_proposal" for m in a["auto_promoted"]) and a["pack"]["pack_version"] == "1.1"
sys.exit(0 if ok else 1)
EOF
wait_for 40 "parse success to recover without anybody touching anything" cond "$LIVE/watch.json" 'd["state"] == "ok" and d["by_family"].get("positional-10", 0) >= 40'
grep -a "RECOVERED" "$LIVE/watch.log" | tail -1
"$VF" gaps --evidence "$LIVE/ev" --trust keys/trust 2>/dev/null | grep -a "pack_activated" | tail -1 | cut -c1-230
phase_done "healed itself: 8 of 10 columns on the operator's earlier evidence, pack 1.1 hot-loaded, alert written; 2 columns withheld and asked — nothing was guessed"

phase F "The two columns the policy would not decide: the operator answers, pack 1.2"
resolve_by_assertion "$LIVE/autoheal/session" "pos_3=connection_info.protocol_num|firmware 2.0 writes the IANA protocol number" "pos_10=src_endpoint.zone|the new column is the initiator's zone"
learn promote --session "$LIVE/autoheal/session" --out "$LIVE/packs/flowtap-v2" --pack-id "$SRC-10" --pack-version 1.1 --withhold-unevidenced > "$LIVE/promote-v2.txt" 2>&1 || { tail -3 "$LIVE/promote-v2.txt"; fail "promote the answered family"; }
learn merge "$LIVE/packs/flowtap-v1" "$LIVE/packs/flowtap-v2" --out "$LIVE/packs/flowtap-source-1.2" --pack-id "$SRC" --pack-version 1.2 || fail "merge"
"$RT" verify-pack --pack "$LIVE/packs/flowtap-source-1.2" || fail "verify merged pack"
reload_packs "$LIVE/packs/flowtap-source-1.2"
wait_for 20 "events carrying the answered columns" bash -c "tail -1 '$LIVE/run-1/out.jsonl' | grep -q '\"zone\"'"
phase_done "pack 1.2 hot-loaded: the zone and the protocol number are mapped now, on the operator's word"

phase G "Backfill: everything quarantined while nobody could read it, replayed from the evidence log"
gen_ctl finish
wait_for 40 "the generators to deliver their backlog and exit" bash -c "! kill -0 $(cat "$LIVE/gen.pid") 2>/dev/null && ! kill -0 $(cat "$LIVE/gen2.pid") 2>/dev/null"
GEN=$(python3 -c 'import json,sys; print(sum(json.load(open(p))["sent"] for p in sys.argv[1:]))' "$LIVE/generator.json" "$LIVE/generator-http.json")
sleep 1.5   # both generators have closed their connections: every line they sent has been framed (the quarantine FILE is buffered by the
            # runtime and only complete at exit, so the monitor's total is not the number to wait on; the runtime's own count is checked below)
# one command back, one command forward: the rollback the alert names, proven on the running runtime, then the current pack again
RELOADS=$(grep -ac "^reloaded:" "$LIVE/run-1/runtime.err")
(cd learning && python tools/autoheal.py rollback --alert "$LIVE/autoheal/alert-latest.json" --packs-file "$LIVE/packs.txt" --runtime-pid "$(cat "$LIVE/runtime.pid")") || fail "rollback"
wait_reloads $((RELOADS + 1)); reload_packs "$LIVE/packs/flowtap-source-1.2"
sleep 1; kill -TERM "$(cat "$LIVE/runtime.pid")"; wait "$(cat "$LIVE/runtime.pid")"; RC=$?; rm -f "$LIVE/runtime.pid"; touch "$LIVE/watch.stop"
grep -aE '^\{' "$LIVE/run-1/runtime.err" | tail -1 > "$LIVE/run-1/stats.json"
[ $RC -eq 0 ] || { tail -3 "$LIVE/run-1/runtime.err"; fail "runtime exited $RC (3 = delivery still owed)"; }
: > "$LIVE/backfill.log"
for sig in "$SIG1" "$SIG2"; do
  (cd learning && python tools/drift.py --quarantine "$LIVE/run-1/q.jsonl" --evidence "$LIVE/ev" --extract-signature "$sig" --out "$LIVE/backfill.part" 2>/dev/null) > /dev/null && cat "$LIVE/backfill.part" >> "$LIVE/backfill.log"
done
rm -f "$LIVE/backfill.part"; mkdir -p "$LIVE/backfill"
"$RT" run --pack "$GOLDEN" --pack "$LIVE/packs/flowtap-source-1.2" --source-id live-backfill-01 --input "$LIVE/backfill.log" --evidence "$LIVE/ev-backfill" \
   --out "$LIVE/backfill/out.jsonl" --quarantine "$LIVE/backfill/q.jsonl" --spool "$LIVE/backfill/spool" --forward "bulk+http://$SINK_ADDR" --forward "http://$LAKE_ADDR/ingest" --forward-drain 20s 2> "$LIVE/backfill/runtime.err" || { tail -3 "$LIVE/backfill/runtime.err"; fail "backfill run"; }
grep -E '^\{' "$LIVE/backfill/runtime.err" | tail -1 > "$LIVE/backfill/stats.json"
phase_done "$(python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); print(s["frames"], "quarantined lines replayed from the evidence log:", s["usable"], "usable,", s["quarantined"], "still quarantined")' "$LIVE/backfill/stats.json")"

phase H "The accounting"
gaps_json
curl -s -m 30 "http://$LAKE_ADDR/flush" > /dev/null   # everything staged becomes Parquet before it is counted
python - "$LIVE" > "$LIVE/lake-count.json" <<'EOF' || fail "the lake could not be read"
import duckdb, glob, json, sys
L = sys.argv[1]
fs = sorted(glob.glob(f"{L}/lake/ext/*/*/*/*/*.parquet"))
con = duckdb.connect()
rows = con.execute(f"SELECT count(*), count(DISTINCT event_id) FROM read_parquet({fs!r})").fetchone() if fs else (0, 0)
fam = dict(con.execute(f"SELECT family_id, count(*) FROM read_parquet({fs!r}) GROUP BY 1").fetchall()) if fs else {}
schemas = {json.dumps(con.execute(f"DESCRIBE SELECT * FROM read_parquet('{f}')").fetchall()) for f in fs}
print(json.dumps({"files": len(fs), "rows": rows[0], "distinct_event_ids": rows[1], "by_family": fam, "distinct_schemas": len(schemas)}))
EOF
python3 - "$LIVE" "$GEN" <<'EOF' | tee "$LIVE/summary.txt"
import json, sys
L, gen = sys.argv[1], int(sys.argv[2])
r = json.load(open(f"{L}/run-1/stats.json")); bf = json.load(open(f"{L}/backfill/stats.json"))
qhash = {json.loads(l)["raw_hash"] for l in open(f"{L}/run-1/q.jsonl")}
linked = all(json.loads(l)["_lineage"]["raw_hash"] in qhash for l in open(f"{L}/backfill/out.jsonl"))
siem = json.load(open(f"{L}/siem.json")); rows = siem["unique_documents"]
lk = json.load(open(f"{L}/lake-count.json")); fam = lk["by_family"]
kinds = {}
for l in open(f"{L}/gaps.json"):
    if l.strip(): k = json.loads(l)["record"]["kind"]; kinds[k] = kinds.get(k, 0) + 1
std = sum(1 for _ in open(f"{L}/run-1/egress-stdout.ndjson"))
w = json.load(open(f"{L}/watch.json")); fired = [e for e in w["events"] if e["state"] == "fired"]; rec = [e for e in w["events"] if e["state"] == "ok"]
print(f"generators sent {gen}  |  evidence records {r['frames']} = live usable {r['usable']} + quarantined-and-retained {r['quarantined']}  |  backfilled {bf['usable']} of {bf['frames']} (raw_hash linked: {linked})  |  SIEM documents {rows} (overwritten on redelivery: {siem['overwritten_documents']})  |  lake rows {lk['rows']} in {lk['files']} Parquet files, {lk['distinct_schemas']} schema(s) {fam}  |  stdout egress {std}")
print(f"evidence-log records that are not events: {kinds}  |  monitor fired {len(fired)}x, recovered {len(rec)}x  |  runtime restarts 0")
ok = (gen == r["frames"] == r["usable"] + r["quarantined"] and bf["frames"] == r["quarantined"] and bf["quarantined"] == 0 and linked and rows == gen and std == r["usable"]
      and lk["rows"] == lk["distinct_event_ids"] == gen and lk["distinct_schemas"] == 1 and siem["rejected"] == 0
      and kinds.get("egress_stalled", 0) >= 1 and kinds.get("egress_resumed", 0) >= 1 and kinds.get("pack_activated", 0) == 5 and len(fired) == 2 and len(rec) == 2 and set(fam) == {"positional-9", "positional-10"})
json.dump({"generated": gen, "frames": r["frames"], "usable": r["usable"], "quarantined": r["quarantined"], "backfilled": bf["usable"], "backfill_linked_by_raw_hash": linked, "rows": rows, "stdout_egress": std,
           "lake_rows": lk["rows"], "lake_files": lk["files"], "lake_distinct_schemas": lk["distinct_schemas"], "siem_overwritten": siem["overwritten_documents"],
           "by_family": fam, "evidence_record_kinds": kinds, "monitor_fired": len(fired), "monitor_recovered": len(rec), "ok": ok}, open(f"{L}/summary.json", "w"), indent=1)
sys.exit(0 if ok else 1)
EOF
[ ${PIPESTATUS[0]} -eq 0 ] || fail "the accounting does not balance (live/summary.txt)"
phase_done "$(head -1 "$LIVE/summary.txt" | cut -c1-200)"

if [ "${ULPF_LIVE_SKIP_PAD:-0}" != "1" ]; then
  phase I "The third case — whitespace drift: the monitor fires, and NO policy can heal it; this one always needs a human"
  bash "$ROOT/demo/live/parse-drop-check.sh" > "$LIVE/parse-drop.txt" 2>&1 || { tail -5 "$LIVE/parse-drop.txt"; fail "parse-drop check"; }
  grep -aE "FIRED|dominant signal|fail to parse" "$LIVE/parse-drop.txt" | cut -c1-220
  phase_done "parse_success_drop fired on a live stream (routed, then refused); re-onboarding cannot fix it: induction ignores the whitespace the spec rejects"
fi
stop_all
echo "live sequence: $(python3 -c "import sys; print(round($(date +%s.%N) - $T_START, 1))")s"

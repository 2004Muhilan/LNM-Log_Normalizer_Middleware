#!/usr/bin/env bash
# The demo: three applications, three pages, everything driven by buttons.
#
#   1 Generator  http://127.0.0.1:8780/   a log-producing application (outside ULPF): connector, format, on/off, drift
#   2 System     http://127.0.0.1:8765/   ULPF: who is connected, onboarding, drift alerts and self-healing, every log in detail
#   3 Database   http://127.0.0.1:8790/   a consumer application (outside ULPF): egress connector, stored events
#
#   bash demo/start-demo.sh            start (a fresh state directory every time: $STATE/app)
#   bash demo/start-demo.sh stop       stop all three (and the runtime)
#   ULPF_DEMO_PROVIDER=fixture bash demo/start-demo.sh     the fallback when the GPU path stalls: team-authored proposals, SAID SO on the page
source "$(dirname "$(readlink -f "$0")")/lib.sh"
cd "$ROOT"
APP="$STATE/app"
stop() {
  for f in generator system database; do [ -f "$APP/$f.pid" ] && kill "$(cat "$APP/$f.pid")" 2>/dev/null; rm -f "$APP/$f.pid"; done
  for _ in $(seq 1 24); do pgrep -f "demo/apps/[gsd][a-z]*.py" > /dev/null || break; sleep 0.5; done   # the system drains the runtime before it exits
  pkill -9 -f "demo/apps/[gsd][a-z]*.py" 2>/dev/null; pkill -f "[p]acks-file $APP/packs.txt" 2>/dev/null; return 0
}
[ -d "$APP" ] && stop
[ "${1:-start}" = "stop" ] && { echo "stopped"; exit 0; }
chmod -R u+w "$APP" 2>/dev/null; rm -rf "$APP"; mkdir -p "$APP/run-1"
[ -x "$RT" ] || { echo "runtime binary missing: bash scripts/keys-bootstrap.sh"; exit 1; }
[ -f "$GOLDEN/pack.json.sig" ] || { echo "golden pack unsigned: bash demo/reset.sh"; exit 1; }
for p in 6515 8516 8765 8780 8790 8791; do freeport_check $p || { echo "port $p is busy (bash demo/start-demo.sh stop; an old live sequence?)"; exit 1; }; done
PROV=(--provider fixture)
if [ "$DEMO_PROVIDER" = "model" ]; then
  curl -s -m 3 "http://127.0.0.1:$LLAMA_PORT/health" | grep -q ok || { echo "llama-server is not up on :$LLAMA_PORT — bash demo/llama-server.sh start   (or ULPF_DEMO_PROVIDER=fixture)"; exit 1; }
  PROV=(--provider model --model-id "$DEMO_MODEL" --server "http://127.0.0.1:$LLAMA_PORT" --backend "cuda ngl=$LLAMA_NGL $MACHINE_LABEL")
else
  echo "FALLBACK: team-authored proposals stand in for the model (the System page says so)"
fi
setsid -f python3 demo/apps/database.py --db "$APP/events.sqlite" --file "$APP/run-1/egress-stdout.ndjson" > "$APP/database.log" 2>&1
setsid -f python3 demo/apps/system.py --state "$APP" --rt "$RT" --golden "$GOLDEN" --python "$(command -v python)" "${PROV[@]}" > "$APP/system.log" 2>&1
setsid -f python3 demo/apps/generator.py --rate "${ULPF_LIVE_RATE:-6}" > "$APP/generator.log" 2>&1
sleep 1.5
pgrep -f "demo/apps/[g]enerator.py" > "$APP/generator.pid"; pgrep -f "demo/apps/[s]ystem.py" > "$APP/system.pid"; pgrep -f "demo/apps/[d]atabase.py" > "$APP/database.pid"
for f in generator system database; do [ -s "$APP/$f.pid" ] || { echo "$f did not start:"; tail -5 "$APP/$f.log"; exit 1; }; done
cat <<EOF
1 Generator  http://127.0.0.1:8780/
2 System     http://127.0.0.1:8765/
3 Database   http://127.0.0.1:8790/
state: $APP   (logs: generator.log system.log database.log; the runtime's: run-1/runtime.err)
EOF

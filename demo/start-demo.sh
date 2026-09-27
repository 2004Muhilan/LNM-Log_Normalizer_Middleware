#!/usr/bin/env bash
# The demo: an application sends logs into ULPF; ULPF delivers to N destinations — here a SIEM and a data lake.
#
#   1 Generator   http://127.0.0.1:8780/      a log-producing application (outside ULPF): connector, format, on/off, drift, attack burst
#   2 System      http://127.0.0.1:8765/      ULPF: who is connected, onboarding, drift alerts and self-healing, every log in detail,
#                                             one status block per destination, SIEM findings -> the original evidence
#   3 Data lake   http://127.0.0.1:8765/lake  OCSF Parquet (Security Lake layout convention), read-only DuckDB queries
#   4 SIEM        http://127.0.0.1:5601/      OpenSearch Dashboards: "ULPF — normalized events", Security Analytics findings
#
#   bash demo/start-demo.sh            start (fresh state: $STATE/app, and a fresh SIEM)
#   bash demo/start-demo.sh stop       stop the apps, the runtime, the lake writer and the SIEM
#   ULPF_DEMO_PROVIDER=fixture ...     team-authored proposals instead of the model (the System page says so)
#   ULPF_SIEM_DASHBOARDS=0 ...         OpenSearch without Dashboards (memory fallback: a screen is lost, not the demo)
#   ULPF_SIEM=fake ...                 no containers at all: the contract-checked bulk stand-in answers on :9200 (no findings)
# Destinations are a list, demo/apps/destinations.json: ULPF has no SIEM- or lake-specific code, only transports and encodings.
source "$(dirname "$(readlink -f "$0")")/lib.sh"
cd "$ROOT"
APP="$STATE/app"
stop() {
  for f in generator system lakewriter fakesiem; do [ -f "$APP/$f.pid" ] && kill "$(cat "$APP/$f.pid")" 2>/dev/null; rm -f "$APP/$f.pid"; done
  for _ in $(seq 1 30); do pgrep -f "demo/apps/[gs][a-z]*.py|adapters/lake/[l]akewriter.py" > /dev/null || break; sleep 0.5; done   # the console drains the runtime, the lake writer flushes
  pkill -9 -f "demo/apps/[gs][a-z]*.py" 2>/dev/null; pkill -f "adapters/lake/[l]akewriter.py" 2>/dev/null; pkill -f "demo/siem/[f]ake_bulk.py --listen 127.0.0.1:9200" 2>/dev/null
  pkill -f "[p]acks-file $APP/packs.txt" 2>/dev/null; return 0
}
if [ "${1:-start}" = "stop" ]; then stop; [ "${ULPF_SIEM:-opensearch}" = "fake" ] || bash demo/siem/siem.sh stop > /dev/null; echo "stopped"; exit 0; fi
[ -d "$APP" ] && stop
chmod -R u+w "$APP" 2>/dev/null; rm -rf "$APP"; mkdir -p "$APP/run-1"
[ -x "$RT" ] || { echo "runtime binary missing: bash scripts/keys-bootstrap.sh"; exit 1; }
[ -f "$GOLDEN/pack.json.sig" ] || { echo "golden pack unsigned: bash demo/reset.sh"; exit 1; }
python -c "import duckdb" 2>/dev/null || { echo "duckdb is not installed in the venv (pip install -r learning/requirements.txt, before going offline)"; exit 1; }
for p in 6515 8516 8765 8780 8792; do freeport_check $p || { echo "port $p is busy (bash demo/start-demo.sh stop; an old live sequence?)"; exit 1; }; done
PROV=(--provider fixture)
if [ "$DEMO_PROVIDER" = "model" ]; then
  curl -s -m 3 "http://127.0.0.1:$LLAMA_PORT/health" | grep -q ok || { echo "llama-server is not up on :$LLAMA_PORT — bash demo/llama-server.sh start   (or ULPF_DEMO_PROVIDER=fixture)"; exit 1; }
  PROV=(--provider model --model-id "$DEMO_MODEL" --server "http://127.0.0.1:$LLAMA_PORT" --backend "cuda ngl=$LLAMA_NGL $MACHINE_LABEL")
else
  echo "FALLBACK: team-authored proposals stand in for the model (the System page says so)"
fi
export ULPF_FAKE_SIEM_STATE="$APP/fake-siem.json"
if [ "${ULPF_SIEM:-opensearch}" = "fake" ]; then
  freeport_check 9200 || { echo "port 9200 is busy (bash demo/siem/siem.sh stop)"; exit 1; }
  setsid -f python3 demo/siem/fake_bulk.py --listen 127.0.0.1:9200 --state "$APP/fake-siem.json" > "$APP/fakesiem.log" 2>&1
  echo "SIEM: the bulk stand-in (ULPF_SIEM=fake) — no Dashboards, no Security Analytics findings"
else
  bash demo/siem/siem.sh start || { echo "the SIEM did not start (memory? try ULPF_SIEM_DASHBOARDS=0, or ULPF_SIEM=fake)"; exit 1; }
fi
setsid -f python adapters/lake/lakewriter.py --lake "$APP/lake" --listen 127.0.0.1:8792 --rotate-seconds "${ULPF_LAKE_ROTATE_SECONDS:-10}" > "$APP/lakewriter.log" 2>&1
setsid -f python demo/apps/system.py --state "$APP" --rt "$RT" --golden "$GOLDEN" --python "$(command -v python)" --lake "$APP/lake" "${PROV[@]}" > "$APP/system.log" 2>&1
setsid -f python3 demo/apps/generator.py --rate "${ULPF_LIVE_RATE:-6}" > "$APP/generator.log" 2>&1
sleep 2
pgrep -f "demo/apps/[g]enerator.py" > "$APP/generator.pid"; pgrep -f "demo/apps/[s]ystem.py" > "$APP/system.pid"; pgrep -f "adapters/lake/[l]akewriter.py" > "$APP/lakewriter.pid"
pgrep -f "demo/siem/[f]ake_bulk.py --listen 127.0.0.1:9200" > "$APP/fakesiem.pid" 2>/dev/null
for f in generator system lakewriter; do [ -s "$APP/$f.pid" ] || { echo "$f did not start:"; tail -5 "$APP/$f.log"; exit 1; }; done
cat <<EOF
1 Generator   http://127.0.0.1:8780/
2 System      http://127.0.0.1:8765/
3 Data lake   http://127.0.0.1:8765/lake
4 SIEM        http://127.0.0.1:5601/app/dashboards#/view/ulpf-overview   (OpenSearch Dashboards; security plugin DISABLED — demo only)
state: $APP   (logs: generator.log system.log lakewriter.log; the runtime's: run-1/runtime.err)
EOF

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
#   ULPF_PROCESSES=N ...               scale-out: N runtime processes on the same ingress ports (SO_REUSEPORT; default 2), each
#                                      with its own evidence store, committer and lake writer (ports 8792..), one lake root
# Destinations are a list, demo/apps/destinations.json: ULPF has no SIEM- or lake-specific code, only transports and encodings.
# The evidence archive is its own slot, not a destination: $APP/evidence-archive, a folder beside the lake. The committer
# runs always (every ${ULPF_COMMIT_EVERY:-5s}): it commits sealed segments and ships them there; the runtime deletes a
# shipped segment after the grace period (ULPF_EVIDENCE_GRACE, default 60s) when every deletion condition holds.
source "$(dirname "$(readlink -f "$0")")/lib.sh"
cd "$ROOT"
APP="$STATE/app"
stop() {
  for f in generator system lakewriter fakesiem committer witness; do [ -f "$APP/$f.pid" ] && kill "$(cat "$APP/$f.pid")" 2>/dev/null; rm -f "$APP/$f.pid"; done
  for _ in $(seq 1 30); do pgrep -f "demo/apps/[gs][a-z]*.py|adapters/lake/[l]akewriter.py --lake $APP/" > /dev/null || break; sleep 0.5; done   # the console drains the runtime, the lake writer flushes
  pkill -9 -f "demo/apps/[gs][a-z]*.py" 2>/dev/null; pkill -f "adapters/lake/[l]akewriter.py --lake $APP/" 2>/dev/null; pkill -f "demo/siem/[f]ake_bulk.py --listen 127.0.0.1:9200" 2>/dev/null
  pkill -f "[p]acks-file $APP/packs.txt" 2>/dev/null; pkill -f "[u]lpf-committer commit --evidence $APP/" 2>/dev/null; pkill -f "[u]lpf-witness .*--listen 127.0.0.1:8796" 2>/dev/null; return 0
}
if [ "${1:-start}" = "stop" ]; then stop; [ "${ULPF_SIEM:-opensearch}" = "fake" ] || bash demo/siem/siem.sh stop > /dev/null; echo "stopped"; exit 0; fi
[ -d "$APP" ] && stop
chmod -R u+w "$APP" 2>/dev/null; rm -rf "$APP"; mkdir -p "$APP/run-1"
[ -x "$RT" ] || { echo "runtime binary missing: bash scripts/keys-bootstrap.sh"; exit 1; }
[ -f "$GOLDEN/pack.json.sig" ] || { echo "golden pack unsigned: bash demo/reset.sh"; exit 1; }
python -c "import duckdb" 2>/dev/null || { echo "duckdb is not installed in the venv (pip install -r learning/requirements.txt, before going offline)"; exit 1; }
N=${ULPF_PROCESSES:-2}
for p in 6515 8516 8765 8780 8796 $(seq 8792 $((8792 + N - 1))); do freeport_check $p || { echo "port $p is busy (bash demo/start-demo.sh stop; an old live sequence?)"; exit 1; }; done
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
# one lake writer per process, all into the same lake root (demo rotation: 10 s — production rotates on size)
for i in $(seq 1 $N); do
  setsid -f python adapters/lake/lakewriter.py --lake "$APP/lake" --listen "127.0.0.1:$((8792 + i - 1))" --writer-id "$i" --rotate-bytes 8MiB \
    --rotate-seconds "${ULPF_LAKE_ROTATE_SECONDS:-10}" > "$APP/lakewriter-$i.log" 2>&1
done
VENDOR=(); if [ -f "$STATE/p6/mixed.log" ] && [ -f "$STATE/p6/source-packs/cisco-asa/pack.json" ]; then VENDOR=(--vendor-packs "$STATE/p6/source-packs" --vendor-capture "$STATE/p6/mixed.log")
else echo "no four-vendor relay: run demo/reset.sh first (it builds the vendor packs and the mixed capture from the corpus)"; fi
# the parser transparency log's WITNESS: a separate process that cosigns the log's checkpoints after checking each is a
# consistent extension of the last (c2sp.org/tlog-witness). On this machine it STANDS IN for an independent site; real
# deployments put witnesses on separate machines. Its state outlives the demo's ($STATE/witness), like the log (tlog/).
[ -x "$ROOT/runtime/bin/ulpf-witness" ] && [ -f keys/dev/ulpf-witness-dev.json ] || { echo "no witness binary or key: bash scripts/keys-bootstrap.sh"; exit 1; }
setsid -f "$ROOT/runtime/bin/ulpf-witness" --key keys/dev/ulpf-witness-dev.json --name ulpf-witness-dev --trust keys/trust --state "$STATE/witness" --listen 127.0.0.1:8796 > "$APP/witness.log" 2>&1
export ULPF_TLOG_WITNESS=http://127.0.0.1:8796
for _ in $(seq 1 30); do curl -s -m 1 http://127.0.0.1:8796/status > /dev/null && break; sleep 0.2; done
"$ROOT/runtime/bin/ulpf-tlog" cosign > "$APP/witness-cosign.log" 2>&1 || echo "the witness did not cosign the log's current checkpoint (see $APP/witness-cosign.log) — packs still load: the policy requires the log's signature and the inclusion proof"
mkdir -p "$APP/evidence-archive"
for i in $(seq 1 $N); do   # one committer per process's evidence store; all ship to the one archive
  S=$([ $i = 1 ] && echo "" || echo "-$i"); mkdir -p "$APP/commit$S"
  ULPF_COMMIT_SEALED=1 setsid -f "$CM" commit --evidence "$APP/ev$S" --commit "$APP/commit$S" --key keys/dev/ulpf-committer-dev.json --every "${ULPF_COMMIT_EVERY:-5s}" \
    --archive "$APP/evidence-archive" > "$APP/committer$S.log" 2>&1
done
setsid -f python demo/apps/system.py --state "$APP" --rt "$RT" --golden "$GOLDEN" --python "$(command -v python)" --lake "$APP/lake" "${VENDOR[@]}" "${PROV[@]}" \
  --archive "$APP/evidence-archive" --commit-dir "$APP/commit" --evidence-grace "${ULPF_EVIDENCE_GRACE:-60s}" --evidence-buffer-cap "${ULPF_EVIDENCE_BUFFER_CAP:-64MiB}" \
  --processes "$N" --lake-port 8792 > "$APP/system.log" 2>&1
setsid -f python3 demo/apps/generator.py --rate "${ULPF_LIVE_RATE:-6}" > "$APP/generator.log" 2>&1
sleep 2
pgrep -f "demo/apps/[g]enerator.py" > "$APP/generator.pid"; pgrep -f "demo/apps/[s]ystem.py" > "$APP/system.pid"; pgrep -f "adapters/lake/[l]akewriter.py --lake $APP/" | head -1 > "$APP/lakewriter.pid"
pgrep -f "demo/siem/[f]ake_bulk.py --listen 127.0.0.1:9200" > "$APP/fakesiem.pid" 2>/dev/null
pgrep -f "[u]lpf-committer commit --evidence $APP/" | head -1 > "$APP/committer.pid"
pgrep -f "[u]lpf-witness .*--listen 127.0.0.1:8796" | head -1 > "$APP/witness.pid"
for f in generator system lakewriter committer witness; do [ -s "$APP/$f.pid" ] || { echo "$f did not start:"; tail -5 "$APP/$f.log" "$APP/$f-1.log" 2>/dev/null; exit 1; }; done
[ "$(pgrep -fc "[u]lpf-committer commit --evidence $APP/")" = "$N" ] && [ "$(pgrep -fc "adapters/lake/[l]akewriter.py --lake $APP/")" = "$N" ] || { echo "not every committer / lake writer started ($N expected)"; exit 1; }
cat <<EOF
1 Generator   http://127.0.0.1:8780/
2 System      http://127.0.0.1:8765/
3 Data lake   http://127.0.0.1:8765/lake
4 SIEM        http://127.0.0.1:5601/app/dashboards#/view/ulpf-overview   (OpenSearch Dashboards; security plugin DISABLED — demo only)
processes: $N ULPF runtimes on the same ports (SO_REUSEPORT), each with its own evidence store, committer and lake writer
state: $APP   (logs: generator.log system.log lakewriter-*.log committer*.log; the runtimes': run-*/runtime.err)
evidence archive: $APP/evidence-archive   (the committer ships; ULPF keeps a short local buffer: $APP/ev)
parser transparency log: $ROOT/tlog, witness http://127.0.0.1:8796 (on this machine: it stands in for an independent site)
EOF

#!/usr/bin/env bash
# THE GATE in one command, in parallel lanes (laptop branch, 2026-09-27). Target: under 15 minutes on the desktop.
#
#   bash scripts/gate.sh            desktop: lanes A, D, G20 and G33 at once
#   bash scripts/gate.sh --laptop   the laptop: no G33 lane (the 33-layer split is desktop-only); D runs after A
#   ULPF_GATE_DEMO_CHECKS=0 ...     without lane D
#
# It runs what the per-phase checks ran — but each thing ONCE. The phase checks are cumulative by design (each re-ran
# the full Go and Python suites, the golden-vector check, the key bootstrap and, in four of them, the invariant-2 image
# build), and three unique tests were run twice each (once to show, once for the exit status); the witness three times.
# Measured on 2026-09-27: the full Go suite ran ~9 times per gate, the Python suite ~8 times.
#
#   shared, once   binaries + dev keys + golden signature (keys-bootstrap), gofmt, go vet, golden vectors
#   lane A         the full Go suite once (-v: no FAIL, no silent SKIP), the Python suite once (-rs: no SKIP), invariant 2
#                  once, then every phase check's UNIQUE part (ULPF_GATE_SHARED=1 skips only what ran once above):
#                  p1 golden vectors by name · p3/p4/p5 fixture walks · p5 boundary + witness · p6 four-vendor build ·
#                  p7 flood/relay tests + demo · p8 named tests, coverage replay, connector smoke, requirement (k), container stage
#   lane D         the demo's destinations: SIEM up, contract check (--limits) against real OpenSearch, apps-check (fixture,
#                  six formats: onboarding, drift, SIEM outage, lake, a finding proven back to the evidence)
#   lane G20/G33   the acceptance criterion: demo/twice.sh and demo/live/twice-live.sh, each lane with its own state
#                  directory, ports, model server and witness container (the two model servers share the GPU)
#
# Logs: /tmp/ulpf-gate/*.log. Exit status 0 only if every lane passed.
set -uo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
ROOTDIR="$PWD"
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
export DOCKER_CONFIG="${DOCKER_CONFIG:-/tmp/ulpf-dockercfg}"; mkdir -p "$DOCKER_CONFIG"; [ -f "$DOCKER_CONFIG/config.json" ] || echo '{}' > "$DOCKER_CONFIG/config.json"
G=/tmp/ulpf-gate; rm -rf "$G"; mkdir -p "$G"
LAPTOP=0; [ "${1:-}" = "--laptop" ] && LAPTOP=1
T0=$(date +%s)
since() { echo $(( $(date +%s) - ${1:-$T0} )); }
note() { echo "[$(printf '%4d' "$(since)")s] $*"; }

note "shared, once: binaries, dev keys, golden signature, gofmt, go vet, golden vectors"
bash scripts/keys-bootstrap.sh > "$G/shared.log" 2>&1 || { note "FAIL: keys-bootstrap (see $G/shared.log)"; exit 1; }
unformatted=$(cd runtime && gofmt -l ./internal ./cmd ./contracts)
[ -z "$unformatted" ] || { note "FAIL: unformatted Go: $unformatted"; exit 1; }
(cd runtime && go vet ./...) >> "$G/shared.log" 2>&1 || { note "FAIL: go vet"; exit 1; }
python contracts/golden/tools/build_vectors.py --check >> "$G/shared.log" 2>&1 || { note "FAIL: golden vectors differ from a fresh regeneration"; exit 1; }
note "shared: ok ($(tail -1 "$G/shared.log" | cut -c1-90))"
export ULPF_GATE_SHARED=1

laneA() {
  local st=0 t
  t=$(date +%s); (cd runtime && go test -count=1 ./... -v) > "$G/go-test.log" 2>&1 || st=1
  local fails skips; fails=$(grep -aE "^(--- FAIL|FAIL\s)" "$G/go-test.log" | head -5); skips=$(grep -aE "^\s*--- SKIP" "$G/go-test.log" | grep -vE "TestKillHelper|TestRecoverHelper")
  [ -z "$skips" ] || { st=1; echo "silent skips: $skips"; }
  echo "go suite: $([ -z "$fails" ] && [ $st = 0 ] && echo "PASS ($(grep -ac '^--- PASS' "$G/go-test.log") tests, 0 skipped)" || echo "FAIL $fails") $(since $t)s"
  t=$(date +%s); (cd learning && python -m pytest -q -rs) > "$G/pytest.log" 2>&1 || st=1
  grep -aq "^SKIPPED" "$G/pytest.log" && { st=1; echo "python: skipped tests"; }
  echo "python suite: $(tail -1 "$G/pytest.log") $(since $t)s"
  t=$(date +%s); bash scripts/invariant2-check.sh > "$G/inv2.log" 2>&1 || st=1; echo "invariant 2: $(tail -1 "$G/inv2.log") $(since $t)s"
  for n in 1 2 3 4 5 6 8; do
    t=$(date +%s); bash scripts/p$n-check.sh > "$G/p$n.log" 2>&1; rc=$?; [ $rc = 0 ] || st=1
    echo "p$n-check (unique part): $([ $rc = 0 ] && echo PASS || echo FAIL) $(since $t)s"
  done
  return $st
}

laneD() {
  local st=0 t
  t=$(date +%s)
  # the four-vendor relay (unified visibility) needs the vendor packs and the mixed capture in the demo's state directory
  D0="${ULPF_DEMO_STATE:-$HOME/ulpf-demo}"
  [ -f "$D0/p6/mixed.log" ] && [ -f "$D0/p6/source-packs/cisco-asa/pack.json" ] || ULPF_P6_WORK="$D0/p6" bash scripts/p6-build-packs.sh > "$G/p6-demo.log" 2>&1 || { echo "vendor packs for the relay did not build"; return 1; }
  bash demo/siem/siem.sh start > "$G/siem.log" 2>&1 || { echo "SIEM did not start"; return 1; }
  python3 demo/siem/contract-check.py --limits > "$G/contract.log" 2>&1 || st=1; echo "contract check: $(tail -1 "$G/contract.log" | cut -c1-80) $(since $t)s"
  t=$(date +%s); ULPF_DEMO_PROVIDER=fixture APPS_SHAPES="positional csv kv json xml leef" bash demo/apps-check.sh > "$G/apps-check.log" 2>&1 || st=1
  echo "apps-check (fixture, six formats, real SIEM): $(tail -1 "$G/apps-check.log") $(since $t)s"
  grep -aE "^(outage|accounting|finding):" "$G/apps-check.log" | cut -c1-160 | sed 's/^/  /'
  return $st
}

laneG() { # ngl unpinned port-offset
  local ngl=$1 unp=$2 off=$3 st=0 t
  export ULPF_DEMO_STATE="$HOME/ulpf-gate/g$ngl/ulpf-demo" ULPF_LLAMA_NGL=$ngl ULPF_DEMO_NGL_UNPINNED=$unp ULPF_LLAMA_PORT=$((8081 + off)) ULPF_LLAMA_NAME="ulpf-gate-llama-$ngl" \
         ULPF_WITNESS_NAME="ulpf-gate-witness-$ngl" ULPF_DEMO_TCP_PORT=$((6514 + off)) ULPF_LIVE_TCP_PORT=$((6515 + off)) ULPF_LIVE_HTTP_PORT=$((8516 + off)) \
         ULPF_LIVE_SINK="127.0.0.1:$((8790 + off))" ULPF_LIVE_LAKE="127.0.0.1:$((8792 + off))"
  mkdir -p "$(dirname "$ULPF_DEMO_STATE")"
  bash demo/llama-server.sh start > "$G/llama-$ngl.log" 2>&1 || { echo "model server ($ngl layers) did not start"; return 1; }
  t=$(date +%s); bash demo/twice.sh > "$G/twice-$ngl.log" 2>&1 || st=1
  echo "six steps twice ($ngl layers): $(grep -aE "SHOWED|DIFFER|FAILED" "$G/twice-$ngl.log" | head -1 | cut -c1-60) | $(grep -a '^total' "$G/twice-$ngl.log") $(since $t)s"
  t=$(date +%s); bash demo/live/twice-live.sh > "$G/live-$ngl.log" 2>&1 || st=1
  echo "live sequence twice ($ngl layers): $(grep -aE "SHOWED|DIFFER|FAILED" "$G/live-$ngl.log" | head -1 | cut -c1-60) | walls $(grep -a '^wall' "$G/live-$ngl.log" | tr '\n' ' ') $(since $t)s"
  bash demo/llama-server.sh stop > /dev/null 2>&1
  return $st
}

run_lane() { # name function args... -> $G/lane-NAME.{log,rc}
  local name=$1; shift
  ( t=$(date +%s); "$@"; rc=$?; echo "lane $name: $([ $rc = 0 ] && echo PASS || echo FAIL) in $(since $t)s"; echo $rc > "$G/lane-$name.rc" ) > "$G/lane-$name.log" 2>&1
}

note "lanes start"
pids=()
run_lane G20 laneG 20 0 1000 & pids+=($!)
[ $LAPTOP = 0 ] && { run_lane G33 laneG 99 1 2000 & pids+=($!); }
if [ $LAPTOP = 1 ]; then   # 10 GB and one small GPU: the SIEM lane waits for the checks lane
  { run_lane A laneA; [ "${ULPF_GATE_DEMO_CHECKS:-1}" = 1 ] && run_lane D laneD; } & pids+=($!)
else
  run_lane A laneA & pids+=($!)
  [ "${ULPF_GATE_DEMO_CHECKS:-1}" = 1 ] && { run_lane D laneD & pids+=($!); }
fi
for p in "${pids[@]}"; do wait "$p"; done
fail=0
for f in "$G"/lane-*.log; do
  echo; echo "---- $(basename "$f" .log)"; cat "$f"
  [ "$(cat "${f%.log}.rc" 2>/dev/null)" = 0 ] || fail=1
done
echo
note "GATE: $([ $fail = 0 ] && echo PASS || echo FAIL) — total $(since)s (logs: $G)"
exit $fail

#!/usr/bin/env bash
# P2 exit checks: build the runtime, regenerate golden vectors (parser_hash + normalized golden),
# run both contract suites, run the runtime tests (golden span maps, adversarial specs, framing,
# evidence, kill-test, corpus replay), then build and test the container image.
set -uo pipefail
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/.."
status=0
bash scripts/keys-bootstrap.sh >/dev/null || { echo "key bootstrap failed"; exit 1; }   # local dev keys + signed golden pack (never committed)
export ULPF_ROOT="$PWD"

echo "=== go: fmt/vet/build runtime binary"
(cd runtime && [ -z "$(gofmt -l ./internal ./cmd ./contracts | tee /dev/stderr)" ] && go vet ./... && mkdir -p bin && go build -o bin/ulpf-runtime ./cmd/ulpf-runtime) || status=1

echo "=== golden vectors (parser_hash from the compiler; normalized golden from the pipeline)"
python contracts/golden/tools/build_vectors.py --check || status=1

echo "=== verify-pack (fail-closed load of the golden pack)"
runtime/bin/ulpf-runtime verify-pack --pack contracts/golden/squid-native || status=1

echo "=== python: golden walk + pytest"
(cd learning && python -m ulpf_contracts --golden | tail -3) || status=1
(cd learning && python -m pytest -q 2>&1 | tail -3) || status=1

echo "=== go: full test suite (includes corpus replay when corpus/cache is present)"
(cd runtime && go test -count=1 ./... 2>&1 | tail -25) || status=1

echo "=== go: replay + kill-test detail"
(cd runtime && go test -count=1 ./internal/dsl/ -run 'Replay|Synthetic' -v 2>&1 | grep -E "^(=== RUN|--- (PASS|FAIL|SKIP))" | grep -E "PASS|FAIL|SKIP" | sed 's/^ *//' | sort | uniq -c)
(cd runtime && go test -count=1 ./internal/pipeline/ -run 'Kill|Quarantine|Golden' -v 2>&1 | grep -E "^--- (PASS|FAIL)")

[ "${ULPF_SKIP_DOCKER:-0}" = "1" ] && echo "=== DOCKER STAGES SKIPPED (ULPF_SKIP_DOCKER=1): container/boundary/witness checks did NOT run"
if [ "${ULPF_SKIP_DOCKER:-0}" != "1" ]; then
  echo "=== container: test stage, then runtime image"
  docker build -q -f runtime/Dockerfile --target test -t ulpf-runtime-test . >/dev/null && echo "container test stage: PASS" || { echo "container test stage: FAIL"; status=1; }
  docker build -q -f runtime/Dockerfile --target runtime -t ulpf-runtime . >/dev/null && echo "runtime image: built ($(docker image inspect ulpf-runtime --format '{{.Size}}' | awk '{printf "%.1f MB", $1/1048576}'))" || { echo "runtime image: FAIL"; status=1; }
  echo "=== container: golden pack through the runtime image (no network, non-root)"
  docker run --rm --network none -v "$PWD/contracts/golden/squid-native:/pack:ro" -v "$PWD/ocsf/pinned:/ocsf/pinned:ro" -v "$PWD/keys/trust:/keys/trust:ro" ulpf-runtime \
    run --pack /pack --input /pack/samples/access.log --evidence /tmp/ev --out - --contracts /contracts --pinned /ocsf/pinned/index.json --trust /keys/trust 2>/tmp/ulpf-stats.json | wc -l | sed 's/^/  events emitted in container: /'
  cat /tmp/ulpf-stats.json 2>/dev/null | sed 's/^/  stats: /'
fi

exit $status

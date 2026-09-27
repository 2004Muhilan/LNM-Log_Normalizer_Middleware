#!/usr/bin/env bash
# P3 exit checks: runtime build (the differential test needs the binary), contract vectors, both
# contract suites, the runtime suite, then the learning-plane suite (trace scenario, invariants 4/5,
# cross-stack differential), then a scripted run of the review CLI.
set -uo pipefail
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/.."
export ULPF_ROOT="$PWD"
status=0
[ "${ULPF_GATE_SHARED:-0}" = 1 ] || { bash scripts/keys-bootstrap.sh >/dev/null || { echo "key bootstrap failed"; exit 1; }; }   # local dev keys + signed golden pack (never committed); run once by scripts/gate.sh
echo "=== runtime build"
(cd runtime && [ -z "$(gofmt -l ./internal ./cmd ./contracts | tee /dev/stderr)" ] && go vet ./... && go build -o bin/ulpf-runtime ./cmd/ulpf-runtime) || status=1
echo "=== golden vectors + contract suites"
[ "${ULPF_GATE_SHARED:-0}" = 1 ] || { python contracts/golden/tools/build_vectors.py --check || status=1; }   # run once by scripts/gate.sh
(cd learning && python -m ulpf_contracts --golden | tail -1) || status=1
echo "=== runtime suite"
[ "${ULPF_GATE_SHARED:-0}" = 1 ] || { (cd runtime && go test -count=1 ./... 2>&1 | grep -vE "no test files") || status=1; }   # run once by scripts/gate.sh
echo "=== learning-plane suite"
[ "${ULPF_GATE_SHARED:-0}" = 1 ] || { (cd learning && python -m pytest -q 2>&1 | tail -5) || status=1; }   # run once by scripts/gate.sh
echo "=== review CLI, scripted (the demo sequence)"
S=/tmp/ulpf-p3-session; rm -rf "$S" /tmp/ulpf-p3-pack
(cd learning && python -m ulpf_learn onboard --samples ../contracts/golden/squid-native/samples/access.log --source-id squid-proxy-01 --operator op-014 --session "$S" | sed 's/^/  /') || status=1
(cd learning && python -m ulpf_learn certificates --session "$S" | sed 's/^/  /') || status=1
(cd learning && python -m ulpf_learn respond --session "$S" --discriminator device_logformat_configuration --input "logformat squid %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %[un %Sh/%<a %mt" | tail -4 | sed 's/^/  /') || status=1
(cd learning && python -m ulpf_learn promote --session "$S" --out /tmp/ulpf-p3-pack --pack-id squid-native-emitted | sed 's/^/  /') || status=1
runtime/bin/ulpf-runtime verify-pack --pack /tmp/ulpf-p3-pack | sed 's/^/  /' || status=1
runtime/bin/ulpf-runtime run --dev-no-evidence-archive --pack /tmp/ulpf-p3-pack --input /tmp/ulpf-p3-pack/samples/access.log --evidence /tmp/ulpf-p3-ev --out /dev/null 2>&1 | tail -1 | sed 's/^/  live lines through the emitted pack: /'
rm -rf /tmp/ulpf-p3-ev
exit $status

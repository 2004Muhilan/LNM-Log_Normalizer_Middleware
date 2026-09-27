#!/usr/bin/env bash
# P1 exit checks: build golden vectors, run the Python suite, run the Go suite.
set -uo pipefail
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/.."
status=0
[ "${ULPF_GATE_SHARED:-0}" = 1 ] || { bash scripts/keys-bootstrap.sh >/dev/null || { echo "key bootstrap failed"; exit 1; }; }   # local dev keys + signed golden pack (never committed); run once by scripts/gate.sh

echo "=== build golden vectors ==="
[ "${ULPF_GATE_SHARED:-0}" = 1 ] || { python contracts/golden/tools/build_vectors.py --check || status=1; }   # run once by scripts/gate.sh

echo "=== python: golden walk ==="
(cd learning && python -m ulpf_contracts --golden) || status=1

echo "=== python: pytest ==="
[ "${ULPF_GATE_SHARED:-0}" = 1 ] || { (cd learning && python -m pytest -q 2>&1 | tail -15) || status=1; }   # run once by scripts/gate.sh

echo "=== go: mod tidy + test ==="
[ "${ULPF_GATE_SHARED:-0}" = 1 ] || { (cd runtime && go mod tidy && go test -count=1 ./... 2>&1 | tail -40) || status=1; }   # run once by scripts/gate.sh

echo "=== go: golden walk (verbose names) ==="
(cd runtime && go test -count=1 ./contracts/ -run TestGoldenVectors -v 2>&1 | grep -E "^(=== RUN|--- (PASS|FAIL)|\s+---)" | grep -E "FAIL|PASS" | sed 's/^ *//' | sort | uniq -c | head -60)

exit $status

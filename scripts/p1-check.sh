#!/usr/bin/env bash
# P1 exit checks: build golden vectors, run the Python suite, run the Go suite.
set -uo pipefail
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/.."
status=0
bash scripts/keys-bootstrap.sh >/dev/null || { echo "key bootstrap failed"; exit 1; }   # local dev keys + signed golden pack (never committed)

echo "=== build golden vectors ==="
python contracts/golden/tools/build_vectors.py || status=1

echo "=== python: golden walk ==="
(cd learning && python -m ulpf_contracts --golden) || status=1

echo "=== python: pytest ==="
(cd learning && python -m pytest -q 2>&1 | tail -15) || status=1

echo "=== go: mod tidy + test ==="
(cd runtime && go mod tidy && go test -count=1 ./... 2>&1 | tail -40) || status=1

echo "=== go: golden walk (verbose names) ==="
(cd runtime && go test -count=1 ./contracts/ -run TestGoldenVectors -v 2>&1 | grep -E "^(=== RUN|--- (PASS|FAIL)|\s+---)" | grep -E "FAIL|PASS" | sed 's/^ *//' | sort | uniq -c | head -60)

exit $status

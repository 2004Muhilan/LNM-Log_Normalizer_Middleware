#!/usr/bin/env bash
# P1 exit checks: build golden vectors, run the Python suite, run the Go suite.
set -uo pipefail
source "$HOME/.ulpf-env"
cd "$(dirname "$(readlink -f "$0")")/.."
status=0

echo "=== build golden vectors ==="
python contracts/golden/tools/build_vectors.py || status=1

echo "=== python: golden walk ==="
(cd learning && python -m ulpf_contracts --golden) || status=1

echo "=== python: pytest ==="
(cd learning && python -m pytest -q 2>&1 | tail -15) || status=1

echo "=== go: mod tidy + test ==="
(cd runtime && go mod tidy && go test ./... 2>&1 | tail -40) || status=1

echo "=== go: golden walk (verbose names) ==="
(cd runtime && go test ./contracts/ -run TestGoldenVectors -v 2>&1 | grep -E "^(=== RUN|--- (PASS|FAIL)|\s+---)" | grep -E "FAIL|PASS" | sed 's/^ *//' | sort | uniq -c | head -60)

exit $status

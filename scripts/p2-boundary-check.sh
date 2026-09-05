#!/usr/bin/env bash
# P2 boundary re-check without the container stages (they are unchanged): mirror test, runtime
# suite, regenerated vectors, both contract suites.
set -uo pipefail
source "$HOME/.ulpf-env"
cd "$(dirname "$(readlink -f "$0")")/.."
export ULPF_ROOT="$PWD"
status=0
(cd runtime && gofmt -w ./internal && go vet ./... && go build -o bin/ulpf-runtime ./cmd/ulpf-runtime) || status=1
echo "=== spec mirror test"
(cd runtime && go test ./internal/spec/ -run TestMirrorMatchesSchema -v 2>&1 | grep -E "^(--- |\s+--- |ok|FAIL|\s+mirror_test)" | sed 's/^ *//') || status=1
echo "=== golden vectors + both suites"
python contracts/golden/tools/build_vectors.py || status=1
(cd learning && python -m ulpf_contracts --golden | tail -1) || status=1
(cd learning && python -m pytest -q 2>&1 | tail -1) || status=1
echo "=== runtime suite"
(cd runtime && go test ./... 2>&1 | grep -vE "no test files") || status=1
echo "=== pipeline stats on the golden samples"
runtime/bin/ulpf-runtime run --pack contracts/golden/squid-native --input contracts/golden/squid-native/samples/access.log --evidence /tmp/ulpf-bc-ev --out /dev/null 2>&1 | tail -1
rm -rf /tmp/ulpf-bc-ev
exit $status
